use sp1_prover::{
    build::try_build_groth16_bn254_artifacts_dev, components::CpuProverComponents,
    utils::get_cycles,
};
use sp1_sdk::{SP1Context, SP1Prover};
use sp1_stark::SP1ProverOpts;
use zkaleido::{time_operation, PerformanceReport, ZkVmHost, ZkVmHostPerf};

use crate::SP1Host;

impl ZkVmHostPerf for SP1Host {
    fn perf_report<'a>(
        &self,
        input: <Self::Input<'a> as zkaleido::ZkVmInputBuilder<'a>>::Input,
    ) -> PerformanceReport {
        let prover = SP1Prover::<CpuProverComponents>::new();
        let elf = self.get_elf();

        let cycles = get_cycles(elf, &input);
        let (_, pk_d, program, vk) = prover.setup(elf);

        let context = SP1Context::default();
        let opts = SP1ProverOpts::auto();
        let (core_proof, prove_core_duration) = time_operation(|| {
            prover
                .prove_core(&pk_d, program, &input, opts, context)
                .unwrap()
        });
        let pv = core_proof.public_values.clone();

        let num_shards = core_proof.proof.0.len();

        let core_bytes = bincode::serialize(&core_proof).unwrap();
        let (_, verify_core_duration) = time_operation(|| {
            prover
                .verify(&core_proof.proof, &vk)
                .expect("Proof verification failed")
        });

        let (compress_proof, compress_duration) =
            time_operation(|| prover.compress(&vk, core_proof, vec![], opts).unwrap());

        let compress_bytes = bincode::serialize(&compress_proof).unwrap();
        println!("recursive proof size: {}", compress_bytes.len());

        let (_, verify_compress_duration) = time_operation(|| {
            prover
                .verify_compressed(&compress_proof, &vk)
                .expect("Proof verification failed")
        });

        let (shrink_proof, shrink_prove_duration) =
            time_operation(|| prover.shrink(compress_proof.clone(), opts).unwrap());

        let (wrap_proof, wrap_prove_duration) =
            time_operation(|| prover.wrap_bn254(shrink_proof.clone(), opts).unwrap());

        let artifacts_dir =
            try_build_groth16_bn254_artifacts_dev(&wrap_proof.vk, &wrap_proof.proof);

        // Warm up the prover.
        prover.wrap_groth16_bn254(wrap_proof.clone(), &artifacts_dir);

        let (groth16_proof, groth16_prove_duration) =
            time_operation(|| prover.wrap_groth16_bn254(wrap_proof, &artifacts_dir));

        prover
            .verify_groth16_bn254(&groth16_proof, &vk, &pv, &artifacts_dir)
            .expect("Proof verification failed");

        let prove_duration = prove_core_duration + compress_duration;
        let core_khz = cycles as f64 / prove_core_duration.as_secs_f64() / 1_000.0;
        let overall_khz = cycles as f64 / prove_duration.as_secs_f64() / 1_000.0;

        // Create the performance report.
        PerformanceReport {
            shards: num_shards,
            cycles,
            speed: (cycles as f64) / prove_core_duration.as_secs_f64(),
            prove_duration: prove_duration.as_secs_f64(),
            core_prove_duration: prove_core_duration.as_secs_f64(),
            core_verify_duration: verify_core_duration.as_secs_f64(),
            core_proof_size: core_bytes.len(),
            core_khz,
            compress_prove_duration: compress_duration.as_secs_f64(),
            compress_verify_duration: verify_compress_duration.as_secs_f64(),
            compress_proof_size: compress_bytes.len(),
            shrink_prove_duration: shrink_prove_duration.as_secs_f64(),
            wrap_prove_duration: wrap_prove_duration.as_secs_f64(),
            groth16_prove_duration: groth16_prove_duration.as_secs_f64(),
            overall_khz,
        }
    }
}
