use sp1_prover::{components::CpuProverComponents, utils::get_cycles};
use sp1_sdk::{SP1Context, SP1Prover};
use sp1_stark::SP1ProverOpts;
use zkaleido::{time_operation, PerformanceReport, ZkVmHost, ZkVmHostPerf};

cfg_if::cfg_if! {
    if #[cfg(not(feature = "mock"))] {
        use sp1_prover::build::try_build_groth16_bn254_artifacts_dev;
        use sp1_sdk::SP1Stdin;
        use sp1_stark::SP1ProverOpts;
        use zkaleido::ProofMetrics;
    }
}

use crate::SP1Host;

impl ZkVmHostPerf for SP1Host {
    fn perf_report<'a>(
        &self,
        input: <Self::Input<'a> as zkaleido::ZkVmInputBuilder<'a>>::Input,
    ) -> PerformanceReport {
        let prover = SP1Prover::<CpuProverComponents>::new();
        let elf = self.get_elf();

        let opts = SP1ProverOpts::auto();
        let context = SP1Context::default();
        let cycles = get_cycles(elf, &input);

        let (_, execution_duration) =
            time_operation(|| prover.execute(elf, &input, context.clone()).unwrap());

        let (core_proof_report, compress_proof_report, groth16_proof_report, shards) = {
            cfg_if::cfg_if! {
                if #[cfg(feature = "mock")] {
                    let shards = cycles as usize / opts.core_opts.shard_size;
                    (None, None, None, shards)
                } else {
                    generate_proof_metrics(prover, elf, cycles, pv, input)
                }
            }
        };

        PerformanceReport::new(
            shards,
            cycles,
            execution_duration.as_secs_f64(),
            core_proof_report,
            compress_proof_report,
            groth16_proof_report,
        )
    }
}

#[cfg(not(feature = "mock"))]
fn generate_proof_metrics(
    prover: SP1Prover,
    elf: &[u8],
    cycles: u64,
    input: SP1Stdin,
) -> (ProofMetrics, ProofMetrics, ProofMetrics, usize) {
    let context = SP1Context::default();
    let opts = SP1ProverOpts::auto();

    let (pv, _) = prover.execute(elf, &input, context.clone()).unwrap();

    // Core Proof
    let (_, pk_d, program, vk) = prover.setup(elf);
    let (core_proof, core_prove_duration) = time_operation(|| {
        prover
            .prove_core(&pk_d, program, &input, opts, context)
            .unwrap()
    });
    let shards = core_proof.proof.0.len();
    let core_bytes = bincode::serialize(&core_proof).unwrap();
    let (_, verify_core_duration) = time_operation(|| {
        prover
            .verify(&core_proof.proof, &vk)
            .expect("Proof verification failed")
    });
    let core_speed = cycles as f64 / core_prove_duration.as_secs_f64() / 1_000.0;
    let core_proof_report = ProofMetrics {
        prove_duration: core_prove_duration.as_secs_f64(),
        verify_duration: verify_core_duration.as_secs_f64(),
        proof_size: core_bytes.len(),
        speed: core_speed,
    };

    // Compressed proof
    let (compress_proof, compress_duration) =
        time_operation(|| prover.compress(&vk, core_proof, vec![], opts).unwrap());
    let compress_bytes = bincode::serialize(&compress_proof).unwrap();
    let (_, verify_compress_duration) = time_operation(|| {
        prover
            .verify_compressed(&compress_proof, &vk)
            .expect("Proof verification failed")
    });
    let compress_speed = cycles as f64 / compress_duration.as_secs_f64() / 1_000.0;
    let compress_proof_report = ProofMetrics {
        prove_duration: compress_duration.as_secs_f64(),
        verify_duration: verify_compress_duration.as_secs_f64(),
        proof_size: compress_bytes.len(),
        speed: compress_speed,
    };

    // Groth16 Proof
    let (shrink_proof, shrink_prove_duration) =
        time_operation(|| prover.shrink(compress_proof.clone(), opts).unwrap());

    let (wrap_proof, wrap_prove_duration) =
        time_operation(|| prover.wrap_bn254(shrink_proof.clone(), opts).unwrap());

    let artifacts_dir = try_build_groth16_bn254_artifacts_dev(&wrap_proof.vk, &wrap_proof.proof);

    // Warm up the prover.
    prover.wrap_groth16_bn254(wrap_proof.clone(), &artifacts_dir);

    let (groth16_proof, groth16_prove_duration) =
        time_operation(|| prover.wrap_groth16_bn254(wrap_proof, &artifacts_dir));

    let groth16_total_duration =
        shrink_prove_duration + wrap_prove_duration + groth16_prove_duration;
    prover
        .verify_groth16_bn254(&groth16_proof, &vk, &pv, &artifacts_dir)
        .expect("Proof verification failed");

    let groth16_speed = cycles as f64 / groth16_total_duration.as_secs_f64() / 1_000.0;
    let groth16_proof_report = ProofMetrics {
        prove_duration: groth16_total_duration.as_secs_f64(),
        verify_duration: 0.0,
        proof_size: groth16_proof.encoded_proof.len(),
        speed: groth16_speed,
    };

    (
        core_proof_report,
        compress_proof_report,
        groth16_proof_report,
        shards,
    )
}
