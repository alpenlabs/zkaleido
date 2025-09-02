use std::rc::Rc;

use risc0_zkvm::{
    get_prover_server, sha::Digest, ExecutorImpl, ProverOpts, ProverServer, Receipt, Session,
    VerifierContext,
};
use zkaleido::{
    time_operation, PerformanceReport, ProofMetrics, ZkVmExecutor, ZkVmHostPerf, ZkVmVkProvider,
};

use crate::Risc0Host;

impl ZkVmHostPerf for Risc0Host {
    fn perf_report<'a>(
        &self,
        input: <Self::Input<'a> as zkaleido::ZkVmInputBuilder<'a>>::Input,
    ) -> zkaleido::PerformanceReport {
        let elf = self.get_elf();
        let image_id = self.vk_commitment().into_inner();

        let opts = ProverOpts::default();
        let prover = get_prover_server(&opts).unwrap();

        // Generate the session.
        let mut exec = ExecutorImpl::from_elf(input, elf).unwrap();
        let (session, execution_duration) = time_operation(|| exec.run().unwrap());
        let shards = session.segments.len();
        let cycles = session.user_cycles;

        // If the environment variable "ZKVM_MOCK" is set to "1" or "true" (case-insensitive),
        // then do not generate the proof metrics
        let (core_proof_report, compressed_proof_report, groth16_proof_report) =
            if std::env::var("ZKVM_MOCK")
                .map(|v| v == "1" || v.to_lowercase() == "true")
                .unwrap_or(false)
            {
                (None, None, None)
            } else {
                gen_proof_metrics(prover, session, image_id, cycles)
            };

        PerformanceReport::new(
            shards,
            cycles,
            execution_duration.as_secs_f64(),
            core_proof_report,
            compressed_proof_report,
            groth16_proof_report,
        )
    }
}

fn gen_proof_metrics(
    prover: Rc<dyn ProverServer>,
    session: Session,
    image_id: [u32; 8],
    cycles: u64,
) -> (
    Option<ProofMetrics>,
    Option<ProofMetrics>,
    Option<ProofMetrics>,
) {
    let (core_proof_report, core_proof) =
        gen_core_proof_metrics(prover.clone(), session, image_id, cycles);

    let (compressed_proof_report, compressed_proof) =
        gen_compressed_proof_metrics(prover.clone(), core_proof, image_id, cycles);

    let groth16_proof_report =
        gen_groth16_proof_metrics(prover, compressed_proof, image_id, cycles);

    (
        Some(core_proof_report),
        Some(compressed_proof_report),
        Some(groth16_proof_report),
    )
}

fn gen_core_proof_metrics(
    prover: Rc<dyn ProverServer>,
    session: Session,
    image_id: impl Into<Digest>,
    cycles: u64,
) -> (ProofMetrics, Receipt) {
    let ctx = VerifierContext::default();
    let (info, core_prove_duration) =
        time_operation(|| prover.prove_session(&ctx, &session).unwrap());
    let receipt = info.receipt;

    // Verify the core proof.
    let ((), core_verify_duration) = time_operation(|| receipt.verify(image_id).unwrap());

    // Calculate speed in KHz
    let speed = cycles as f64 / core_prove_duration.as_secs_f64() / 1_000.0;

    let report = ProofMetrics {
        prove_duration: core_prove_duration.as_secs_f64(),
        verify_duration: core_verify_duration.as_secs_f64(),
        proof_size: receipt.seal_size(),
        speed,
    };

    (report, receipt)
}

fn gen_compressed_proof_metrics(
    prover: Rc<dyn ProverServer>,
    core_receipt: Receipt,
    image_id: impl Into<Digest>,
    cycles: u64,
) -> (ProofMetrics, Receipt) {
    // Now compress the proof with recursion.
    let (compressed_proof, compress_prove_duration) = time_operation(|| {
        prover
            .compress(&ProverOpts::succinct(), &core_receipt)
            .unwrap()
    });

    // Verify the recursive proof
    let ((), recursive_verify_duration) =
        time_operation(|| compressed_proof.verify(image_id).unwrap());

    // Calculate speed in KHz
    let speed = cycles as f64 / compress_prove_duration.as_secs_f64() / 1_000.0;

    let report = ProofMetrics {
        prove_duration: compress_prove_duration.as_secs_f64(),
        verify_duration: recursive_verify_duration.as_secs_f64(),
        proof_size: compressed_proof.seal_size(),
        speed,
    };

    (report, compressed_proof)
}

fn gen_groth16_proof_metrics(
    prover: Rc<dyn ProverServer>,
    compressed_receipt: Receipt,
    _image_id: impl Into<Digest>,
    cycles: u64,
) -> ProofMetrics {
    let (bn254_proof, bn254_compress_duration) = time_operation(|| {
        prover
            .identity_p254(compressed_receipt.inner.succinct().unwrap())
            .unwrap()
    });
    let seal_bytes = bn254_proof.get_seal_bytes();
    let (groth16_proof, groth16_duration) =
        time_operation(|| risc0_groth16::prove::shrink_wrap(&seal_bytes).unwrap());

    let total_duration = bn254_compress_duration + groth16_duration;
    let speed = cycles as f64 / total_duration.as_secs_f64() / 1_000.0;

    // TODO: add verification

    ProofMetrics {
        prove_duration: total_duration.as_secs_f64(),
        verify_duration: 0.0, // TODO fix
        proof_size: groth16_proof.to_vec().len(),
        speed,
    }
}
