use std::path::Path;

use platform_kernel::{
    DomainInputs, EvalMode, TargetManifest, compute_domain_config_digest,
    compute_engine_config_digest, evaluate_domain,
};

use crate::atomic_io::write_pretty_json_atomic;
use crate::ops::{SimOptions, load_bundle, parse_domain_tier};

pub fn cmd_promote(
    root: &Path,
    domain_str: &str,
    engine_digest: &str,
    dry_run: bool,
) -> Result<(), String> {
    let tier = parse_domain_tier(domain_str)?;
    let bundle = load_bundle(root, &[tier], &SimOptions::default())?;
    let files = &bundle.domains[&tier];

    let engine_cfg_digest = compute_engine_config_digest(&files.config.engine_config);
    let domain_cfg_digest = compute_domain_config_digest(&files.config);
    let same_tuple = engine_digest == files.observed.engine_digest
        && engine_cfg_digest == files.observed.engine_config_digest
        && domain_cfg_digest == files.observed.domain_config_digest;
    let next_gen = if same_tuple {
        files.observed.generation
    } else {
        files.observed.generation + 1
    };

    let candidate = TargetManifest {
        schema: files.target.schema.clone(),
        domain: tier,
        generation: next_gen,
        expected_observed_generation: files.observed.generation,
        engine_digest: engine_digest.to_string(),
        engine_config_digest: engine_cfg_digest,
        domain_config_digest: domain_cfg_digest,
    };

    let eval = evaluate_domain(&DomainInputs {
        tier,
        mode: EvalMode::Simulate,
        now_epoch_s: bundle.now_epoch_s,
        target: &candidate,
        config: &files.config,
        observed: &files.observed,
        catalog: &bundle.catalog,
        ledger: &bundle.ledger,
        trust_root: &bundle.trust_root,
        checkpoint: bundle.checkpoint.as_ref(),
        oidc_policy: None,
        oidc_claims: None,
    });
    if !eval.is_valid() {
        return Err(format!(
            "promotion refused for `{}`: {:?}",
            tier.as_str(),
            eval.violations
        ));
    }
    if !dry_run {
        write_pretty_json_atomic(
            &root.join("domains").join(tier.as_str()).join("target.json"),
            &candidate,
        )?;
    }
    println!(
        "[promote] domain={} dry_run={dry_run} action={:?} gen={next_gen}",
        tier.as_str(),
        eval.action
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    use platform_kernel::DomainTier;

    use crate::ops::{SimOptions, evaluate_selected_domains};

    #[test]
    fn single_domain_mount_loads_only_requested_prod_observation() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let obs_only_prod = std::env::temp_dir().join(format!("platform-single-obs-{nanos}"));
        fs::create_dir_all(&obs_only_prod).unwrap();
        fs::copy(
            root.join("observations/prod.json"),
            obs_only_prod.join("prod.json"),
        )
        .unwrap();

        let opts = SimOptions {
            observations_dir: Some(obs_only_prod.clone()),
            ..SimOptions::default()
        };
        let receipt = evaluate_selected_domains(root, &[DomainTier::Prod], &opts).unwrap();
        assert!(receipt.all_valid);
        let _ = fs::remove_dir_all(&obs_only_prod);
    }
}
