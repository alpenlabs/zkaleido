use std::{cell::RefCell, collections::VecDeque};

use bincode::deserialize;
use zkaleido::{ZkVmEnv, ZkVmEnvSerde};

#[derive(Clone, Debug)]
pub struct EnvState {
    input_bufs: VecDeque<Vec<u8>>,
    output_bufs: Vec<Vec<u8>>,
}

impl EnvState {
    pub fn new(input_bufs: VecDeque<Vec<u8>>) -> Self {
        Self {
            input_bufs,
            output_bufs: Vec::new(),
        }
    }

    fn pop_next_input(&mut self) -> Option<Vec<u8>> {
        self.input_bufs.pop_front()
    }

    fn push_output(&mut self, output: Vec<u8>) {
        self.output_bufs.push(output);
    }

    pub(crate) fn into_outputs(self) -> Vec<Vec<u8>> {
        self.output_bufs
    }
}

#[derive(Clone, Debug)]
pub struct ProcessZkVmEnv {
    state: RefCell<EnvState>,
}

impl ProcessZkVmEnv {
    pub fn new(state: EnvState) -> Self {
        Self {
            state: RefCell::new(state),
        }
    }

    pub fn into_state(self) -> EnvState {
        self.state.into_inner()
    }
}

impl ZkVmEnv for ProcessZkVmEnv {
    fn read_buf(&self) -> Vec<u8> {
        let mut state = self.state.borrow_mut();
        state.pop_next_input().expect("host/env: no more inputs")
    }

    fn commit_buf(&self, raw_output: &[u8]) {
        let mut state = self.state.borrow_mut();
        state.push_output(raw_output.to_vec());
    }

    fn verify_native_proof(&self, _vk_digest: &[u32; 8], _public_values: &[u8]) {
        // TODO(trey): implement something plausible for this
        todo!()
    }
}
