use std::rc::Rc;

use risc0_zkvm::{
    get_prover_server, sha::Digest, ExecutorImpl, ProverOpts, ProverServer, Receipt, Session,
    VerifierContext,
};
use zkaleido::{time_operation, PerformanceReport, ProofReport, ZkVmHost, ZkVmHostPerf};

use crate::Risc0Host;

impl ZkVmHostPerf for Risc0Host {
    fn perf_report<'a>(
        &self,
        input: <Self::Input<'a> as zkaleido::ZkVmInputBuilder<'a>>::Input,
    ) -> zkaleido::PerformanceReport {
        let elf = self.get_elf();
        let image_id = self.get_verification_key_commitment().into_inner();

        let opts = ProverOpts::default();
        let prover = get_prover_server(&opts).unwrap();

        // Generate the session.
        let mut exec = ExecutorImpl::from_elf(input, elf).unwrap();
        let (session, execution_duration) = time_operation(|| exec.run().unwrap());
        let shards = session.segments.len();
        let cycles = session.user_cycles;

        let (core_proof_report, core_proof) = core_proof_report(prover.clone(), session, image_id);

        let (compressed_proof_report, compressed_proof) =
            compressed_proof_report(prover.clone(), core_proof, image_id, cycles);

        let groth16_proof_report =
            groth16_proof_receipt(prover, compressed_proof, image_id, cycles);

        PerformanceReport::new(
            shards,
            cycles,
            execution_duration.as_secs_f64(),
            Some(core_proof_report),
            Some(compressed_proof_report),
            Some(groth16_proof_report),
        )
    }
}

fn core_proof_report(
    prover: Rc<dyn ProverServer>,
    session: Session,
    image_id: impl Into<Digest>,
) -> (ProofReport, Receipt) {
    let ctx = VerifierContext::default();
    let (info, core_prove_duration) =
        time_operation(|| prover.prove_session(&ctx, &session).unwrap());
    let receipt = info.receipt;
    let cycles = info.stats.total_cycles;

    // Verify the core proof.
    let ((), core_verify_duration) = time_operation(|| receipt.verify(image_id).unwrap());

    // Calculate speed in KHz
    let speed = cycles as f64 / core_prove_duration.as_secs_f64() / 1_000.0;

    let report = ProofReport {
        prove_duration: core_prove_duration.as_secs_f64(),
        verify_duration: core_verify_duration.as_secs_f64(),
        proof_size: receipt.seal_size(),
        speed,
    };

    (report, receipt)
}

fn compressed_proof_report(
    prover: Rc<dyn ProverServer>,
    core_receipt: Receipt,
    image_id: impl Into<Digest>,
    cycles: u64,
) -> (ProofReport, Receipt) {
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

    let report = ProofReport {
        prove_duration: compress_prove_duration.as_secs_f64(),
        verify_duration: recursive_verify_duration.as_secs_f64(),
        proof_size: compressed_proof.seal_size(),
        speed,
    };

    (report, compressed_proof)
}

fn groth16_proof_receipt(
    prover: Rc<dyn ProverServer>,
    compressed_receipt: Receipt,
    _image_id: impl Into<Digest>,
    cycles: u64,
) -> ProofReport {
    let (bn254_proof, bn254_compress_duration) = time_operation(|| {
        prover
            .identity_p254(compressed_receipt.inner.succinct().unwrap())
            .unwrap()
    });
    let seal_bytes = bn254_proof.get_seal_bytes();
    let (groth16_proof, groth16_duration) =
        time_operation(|| risc0_zkvm::stark_to_snark(&seal_bytes).unwrap());

    let total_duration = bn254_compress_duration + groth16_duration;
    let speed = cycles as f64 / total_duration.as_secs_f64() / 1_000.0;

    // TODO: add verification

    ProofReport {
        prove_duration: total_duration.as_secs_f64(),
        verify_duration: 0.0, // TODO fix
        proof_size: groth16_proof.to_vec().len(),
        speed,
    }
}
