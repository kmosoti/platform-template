use std::path::Path;

use ed25519_dalek::SigningKey;
use platform_kernel::{
    AttestationLedger, AttestationRecord, CatalogEngine, DomainConfig, DomainTier, EngineCatalog,
    GENESIS_HASH, Observation, Predicate, ProvenanceStatus, TargetManifest, TrustRoot,
    TrustedCheckpoint, TrustedVerifier, compute_domain_config_digest, compute_engine_config_digest,
    encode_hex, sha256_prefixed, sign_attestation_record, sign_checkpoint,
};
use sha2::{Digest, Sha256};

use crate::archive_verify::verify_release_archive_and_manifest;
use crate::atomic_io::write_pretty_json_atomic;
use crate::ops::read_json;

const DEMO_EVAL_EPOCH_S: u64 = 1_795_000_000;
const DEMO_CHECKPOINT_EPOCH_S: u64 = 1_794_999_000;
const DEMO_ISSUED_S: u64 = 1_794_900_000;
const DEMO_EXPIRES_S: u64 = 1_797_500_000;

pub fn fixture_signing_seed(key_id: &str) -> [u8; 32] {
    let digest = Sha256::digest(format!("platform-template-fixture-demo-v1:{key_id}").as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn verifier_entry(
    key_id: &str,
    predicates: Vec<Predicate>,
    domains: Vec<DomainTier>,
    can_sign_checkpoints: bool,
) -> TrustedVerifier {
    let sk = SigningKey::from_bytes(&fixture_signing_seed(key_id));
    TrustedVerifier {
        key_id: key_id.to_string(),
        algorithm: "ed25519".to_string(),
        public_key_hex: encode_hex(sk.verifying_key().as_bytes()),
        allowed_predicates: predicates,
        allowed_domains: domains,
        can_sign_checkpoints,
    }
}

pub fn build_fixture_trust_root() -> TrustRoot {
    TrustRoot {
        schema: "platform.trust-root/v1".to_string(),
        trust_mode: "fixture-demo".to_string(),
        fixture_mode: true,
        verifiers: vec![
            verifier_entry(
                "ci-sim-bot",
                vec![Predicate::SimPassed],
                vec![DomainTier::Dev, DomainTier::Staging, DomainTier::Prod],
                false,
            ),
            verifier_entry(
                "dev-reconciler",
                vec![Predicate::DevConverged],
                vec![DomainTier::Dev],
                false,
            ),
            verifier_entry(
                "staging-soak-observer",
                vec![Predicate::SoakWithinBounds],
                vec![DomainTier::Staging],
                false,
            ),
            verifier_entry(
                "prod-release-approver",
                vec![Predicate::PolicySigned, Predicate::Revoked],
                vec![DomainTier::Prod],
                false,
            ),
            verifier_entry("checkpoint-authority", vec![], vec![], true),
        ],
    }
}

/// Explicitly seeds the repository's initial demo fixture state. Never called by `import-service-release`.
pub fn cmd_seed_demo_fixtures(
    root: &Path,
    manifest_opt: Option<&Path>,
    archive_opt: Option<&Path>,
) -> Result<(), String> {
    let mut catalog: EngineCatalog = read_json(&root.join("catalog/engines.json"))?;
    if let (Some(manifest_path), Some(archive_path)) = (manifest_opt, archive_opt) {
        let verified_v010: CatalogEngine = verify_release_archive_and_manifest(
            manifest_path,
            archive_path,
            ProvenanceStatus::UnverifiedLocal,
            None,
        )?;
        if let Some(slot) = catalog
            .engines
            .iter_mut()
            .find(|e| e.version == verified_v010.version)
        {
            *slot = verified_v010;
        } else {
            catalog.engines.push(verified_v010);
        }
        write_pretty_json_atomic(&root.join("catalog/engines.json"), &catalog)?;
    }

    let find_ver = |v: &str| {
        catalog
            .engines
            .iter()
            .find(|e| e.version == v)
            .ok_or_else(|| format!("catalog missing `{v}` entry"))
    };
    let (v010, v020) = (find_ver("0.1.0")?, find_ver("0.2.0")?);

    let mut prod_cfg_dig = String::new();
    let mut eng_cfg_dig = String::new();

    for tier in DomainTier::ALL {
        let cfg: DomainConfig =
            read_json(&root.join("domains").join(tier.as_str()).join("config.json"))?;
        let eng_dig = compute_engine_config_digest(&cfg.engine_config);
        let dom_dig = compute_domain_config_digest(&cfg);
        eng_cfg_dig = eng_dig.clone();
        if tier == DomainTier::Prod {
            prod_cfg_dig = dom_dig.clone();
        }

        let tgt_path = root.join("domains").join(tier.as_str()).join("target.json");
        let mut tgt: TargetManifest = read_json(&tgt_path)?;
        tgt.engine_digest = if tier == DomainTier::Dev {
            v020.engine_digest.clone()
        } else {
            v010.engine_digest.clone()
        };
        tgt.engine_config_digest = eng_dig.clone();
        tgt.domain_config_digest = dom_dig.clone();
        write_pretty_json_atomic(&tgt_path, &tgt)?;

        let obs_path = root
            .join("observations")
            .join(format!("{}.json", tier.as_str()));
        let mut obs: Observation = read_json(&obs_path)?;
        obs.engine_digest = v010.engine_digest.clone();
        obs.engine_config_digest = eng_dig;
        obs.domain_config_digest = dom_dig;
        write_pretty_json_atomic(&obs_path, &obs)?;
    }

    write_pretty_json_atomic(
        &root.join("trust/verifiers.json"),
        &build_fixture_trust_root(),
    )?;

    let specs = [
        (
            "att-0001-v010-sim",
            Predicate::SimPassed,
            None,
            None,
            &v010.engine_digest,
            Some(eng_cfg_dig.as_str()),
            None,
            "ci-sim-bot",
        ),
        (
            "att-0002-v010-dev-conv",
            Predicate::DevConverged,
            Some(DomainTier::Dev),
            None,
            &v010.engine_digest,
            Some(eng_cfg_dig.as_str()),
            None,
            "dev-reconciler",
        ),
        (
            "att-0003-v010-soak",
            Predicate::SoakWithinBounds,
            Some(DomainTier::Staging),
            None,
            &v010.engine_digest,
            Some(eng_cfg_dig.as_str()),
            None,
            "staging-soak-observer",
        ),
        (
            "att-0004-v010-prod-policy",
            Predicate::PolicySigned,
            Some(DomainTier::Prod),
            Some(1),
            &v010.engine_digest,
            None,
            Some(prod_cfg_dig.as_str()),
            "prod-release-approver",
        ),
        (
            "att-0005-v020-sim",
            Predicate::SimPassed,
            None,
            None,
            &v020.engine_digest,
            Some(eng_cfg_dig.as_str()),
            None,
            "ci-sim-bot",
        ),
    ];

    let mut prev = GENESIS_HASH.to_string();
    let mut records = Vec::with_capacity(specs.len());
    for (id, pred, dom, target_gen, eng, ecfg, dcfg, key_id) in specs {
        let mut rec = AttestationRecord {
            attestation_id: id.to_string(),
            predicate: pred,
            domain: dom,
            target_generation: target_gen,
            engine_digest: eng.clone(),
            engine_config_digest: ecfg.map(ToString::to_string),
            domain_config_digest: dcfg.map(ToString::to_string),
            evidence_digest: sha256_prefixed(format!("evidence:{id}:{eng}").as_bytes()),
            issued_at_epoch_s: DEMO_ISSUED_S,
            expires_at_epoch_s: Some(DEMO_EXPIRES_S),
            key_id: key_id.to_string(),
            prev_hash: prev,
            record_hash: String::new(),
            signature: String::new(),
        };
        sign_attestation_record(&mut rec, &fixture_signing_seed(key_id));
        prev = rec.record_hash.clone();
        records.push(rec);
    }

    let mut cp = TrustedCheckpoint {
        schema: "platform.ledger-checkpoint/v1".to_string(),
        fixture_mode: true,
        stream_id: "platform-attestations-v1".to_string(),
        ledger_len: records.len(),
        head_record_hash: prev,
        checkpoint_epoch_s: DEMO_CHECKPOINT_EPOCH_S,
        max_staleness_s: 86_400,
        policy_version: 1,
        key_id: "checkpoint-authority".to_string(),
        signature: String::new(),
    };
    sign_checkpoint(&mut cp, &fixture_signing_seed("checkpoint-authority"));
    write_pretty_json_atomic(&root.join("attestations/checkpoint.json"), &cp)?;

    let ledger = AttestationLedger {
        schema: "platform.attestation-ledger/v1".to_string(),
        stream_id: "platform-attestations-v1".to_string(),
        fixture_mode: true,
        demo_eval_epoch_s: Some(DEMO_EVAL_EPOCH_S),
        records,
    };
    write_pretty_json_atomic(&root.join("attestations/ledger.json"), &ledger)?;
    println!(
        "[seed-demo-fixtures] seeded demo catalog, targets, observations, trust root, ledger, and checkpoint"
    );
    Ok(())
}
