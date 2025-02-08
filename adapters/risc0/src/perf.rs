use risc0_zkvm::{default_prover, ProverOpts};
use zkaleido::{time_operation, PerformanceReport, ZkVmHost, ZkVmHostPerf};

use crate::Risc0Host;

impl ZkVmHostPerf for Risc0Host {
    fn perf_report<'a>(
        &self,
        input: <Self::Input<'a> as zkaleido::ZkVmInputBuilder<'a>>::Input,
    ) -> zkaleido::PerformanceReport {
        let elf = self.get_elf();
        let image_id = self.get_verification_key_commitment().into_inner();

        let prover = default_prover();

        let opts = ProverOpts::default();
        let (info, core_prove_duration) =
            time_operation(|| prover.prove_with_opts(input, elf, &opts).unwrap());
        let cycles = info.stats.total_cycles;

        let receipt = info.receipt;

        let composite_receipt = receipt.inner.composite().unwrap();
        let num_segments = composite_receipt.segments.len();

        // Get the core proof size by summing across all segments.
        let mut core_proof_size = 0;
        for segment in composite_receipt.segments.iter() {
            core_proof_size += segment.seal.len() * 4;
        }

        // Verify the core proof.
        let ((), core_verify_duration) = time_operation(|| receipt.verify(image_id).unwrap());

        // Now compress the proof with recursion.
        let (compressed_proof, compress_prove_duration) =
            time_operation(|| prover.compress(&ProverOpts::succinct(), &receipt).unwrap());

        // Verify the recursive proof
        let ((), recursive_verify_duration) =
            time_operation(|| compressed_proof.verify(image_id).unwrap());

        let succinct_receipt = compressed_proof.inner.succinct().unwrap();

        // Bn254 wrapping duration
        let (bn254_proof, wrap_prove_duration) = time_operation(|| {
            prover
                .compress(&ProverOpts::succinct(), &compressed_proof)
                .unwrap()
        });

        println!("Running groth16 wrapper");
        let (_groth16_proof, groth16_prove_duration) =
            time_operation(|| prover.compress(&ProverOpts::groth16(), &bn254_proof));

        println!("Done running groth16");

        // Get the recursive proof size.
        let recursive_proof_size = succinct_receipt.seal.len() * 4;
        let prove_duration = core_prove_duration + compress_prove_duration;

        let core_khz = cycles as f64 / core_prove_duration.as_secs_f64() / 1_000.0;
        let compress_khz = cycles as f64 / compress_prove_duration.as_secs_f64() / 1_000.0;
        let overall_khz = cycles as f64 / prove_duration.as_secs_f64() / 1_000.0;

        // Create the performance report.
        PerformanceReport {
            shards: num_segments,
            cycles,
            speed: (cycles as f64) / prove_duration.as_secs_f64(),
            prove_duration: prove_duration.as_secs_f64(),

            core_prove_duration: core_prove_duration.as_secs_f64(),
            core_verify_duration: core_verify_duration.as_secs_f64(),
            core_proof_size,
            core_khz,

            compress_prove_duration: compress_prove_duration.as_secs_f64(),
            compress_verify_duration: recursive_verify_duration.as_secs_f64(),
            compress_proof_size: recursive_proof_size,
            compress_khz,

            overall_khz,
            shrink_prove_duration: 0f64,
            wrap_prove_duration: wrap_prove_duration.as_secs_f64(),
            groth16_prove_duration: groth16_prove_duration.as_secs_f64(),
        }
    }
}
