use std::env::var;

use sp1_core_executor::SP1CoreOpts;
use sp1_sdk::{
    ProvingKey, SP1Proof, SP1ProofMode, SP1ProofWithPublicValues, SP1ProvingKey, SP1Stdin,
    blocking::{CpuProver, ProveRequest, Prover, ProverClient},
};
use zkaleido::{PerformanceReport, ProofMetrics, ZkVmHostPerf, time_operation};

use crate::SP1Host;

impl ZkVmHostPerf for SP1Host {
    fn perf_report<'a>(
        &self,
        input: <Self::Input<'a> as zkaleido::ZkVmInputBuilder<'a>>::Input,
    ) -> PerformanceReport {
        let execution_client = ProverClient::builder().light().build();
        let proving_client = ProverClient::builder().cpu().build();
        let elf = self.proving_key.elf().clone();

        let ((_, report), execution_duration) =
            time_operation(|| execution_client.execute(elf, input.clone()).run().unwrap());

        let cycles = report.total_instruction_count();
        let shards = estimated_shards(cycles);

        let (core_proof_report, compressed_proof_report, groth16_proof_report) = if var("ZKVM_MOCK")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false)
        {
            (None, None, None)
        } else {
            (
                Some(gen_proof_metric(
                    &proving_client,
                    &self.proving_key,
                    input.clone(),
                    SP1ProofMode::Core,
                    cycles,
                )),
                Some(gen_proof_metric(
                    &proving_client,
                    &self.proving_key,
                    input.clone(),
                    SP1ProofMode::Compressed,
                    cycles,
                )),
                Some(gen_proof_metric(
                    &proving_client,
                    &self.proving_key,
                    input,
                    SP1ProofMode::Groth16,
                    cycles,
                )),
            )
        };

        PerformanceReport::new(
            shards,
            cycles,
            report.gas(),
            execution_duration.as_secs_f64(),
            core_proof_report,
            compressed_proof_report,
            groth16_proof_report,
        )
    }
}

fn gen_proof_metric(
    client: &CpuProver,
    proving_key: &SP1ProvingKey,
    input: SP1Stdin,
    proof_mode: SP1ProofMode,
    cycles: u64,
) -> ProofMetrics {
    let (proof, prove_duration) = time_operation(|| match proof_mode {
        SP1ProofMode::Core => client.prove(proving_key, input).core().run().unwrap(),
        SP1ProofMode::Compressed => client.prove(proving_key, input).compressed().run().unwrap(),
        SP1ProofMode::Plonk => client.prove(proving_key, input).plonk().run().unwrap(),
        SP1ProofMode::Groth16 => client.prove(proving_key, input).groth16().run().unwrap(),
    });

    let (_, verify_duration) = time_operation(|| {
        client
            .verify(&proof, proving_key.verifying_key(), None)
            .expect("Proof verification failed")
    });

    ProofMetrics {
        prove_duration: prove_duration.as_secs_f64(),
        verify_duration: verify_duration.as_secs_f64(),
        proof_size: proof_size(&proof),
        speed: cycles as f64 / prove_duration.as_secs_f64() / 1_000.0,
    }
}

fn proof_size(proof: &SP1ProofWithPublicValues) -> usize {
    match &proof.proof {
        SP1Proof::Groth16(_) | SP1Proof::Plonk(_) => proof.bytes().len(),
        _ => bincode::serialize(proof).unwrap().len(),
    }
}

fn estimated_shards(cycles: u64) -> usize {
    let shard_size = SP1CoreOpts::default().shard_size;
    (cycles as usize).div_ceil(shard_size)
}
