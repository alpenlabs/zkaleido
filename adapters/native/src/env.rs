use std::cell::RefCell;

use zkaleido::ZkVmEnv;

/// Encapsulates the mutable state of the NativeMachine.
#[derive(Debug, Clone)]
pub struct NativeMachineState {
    /// Pointer to the current position in the input.
    pub input_ptr: usize,
    /// Buffer to store the output.
    pub output: Vec<u8>,
}

/// A native implementation of the [`ZkVmEnv`]
///
/// This uses interior mutability with [`RefCell`] to conform to the [`ZkVmEnv`] trait, which
/// requires methods to take an immutable reference to `self`.
#[derive(Debug, Clone)]
pub struct NativeMachine {
    /// A vector containing chunks of serialized input data.
    ///
    /// Each element in the vector represents a separate input that can be deserialized and
    /// processed.
    pub inputs: Vec<Vec<u8>>,

    /// Encapsulated mutable state for the machine.
    pub state: RefCell<NativeMachineState>,
}

impl NativeMachine {
    /// Creates a new, empty `NativeMachine` instance.
    ///
    /// # Returns
    ///
    /// A `NativeMachine` with an empty list of inputs and a freshly initialized
    /// internal state. The internal state (`NativeMachineState`) manages the
    /// machine's pointer to the next input element and captures any output
    /// data produced by the machine during execution.
    pub fn new() -> Self {
        let state = RefCell::new(NativeMachineState {
            input_ptr: 0,
            output: Vec::new(),
        });
        let inputs = Vec::new();
        Self { inputs, state }
    }

    /// Appends a pre-serialized byte slice to the machine's list of inputs.
    pub fn write_slice(&mut self, input: Vec<u8>) {
        self.inputs.push(input);
    }
}

impl Default for NativeMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl ZkVmEnv for NativeMachine {
    fn read_buf(&self) -> Vec<u8> {
        let mut state = self.state.borrow_mut();
        let buf = self.inputs[state.input_ptr].clone();
        state.input_ptr += 1;
        buf
    }

    fn read_serde<T: serde::de::DeserializeOwned>(&self) -> T {
        let bytes = self.read_buf();
        bincode::deserialize(&bytes).expect("bincode deserialization failed")
    }

    fn commit_buf(&self, raw_output: &[u8]) {
        self.state.borrow_mut().output.extend_from_slice(raw_output);
    }

    fn commit_serde<T: serde::Serialize>(&self, output: &T) {
        let bytes = bincode::serialize(output).expect("bincode serialization failed");
        self.commit_buf(&bytes);
    }

    fn verify_native_proof(&self, _vk_digest: &[u32; 8], _public_values: &[u8]) {}

    fn read_verified_serde<T: serde::de::DeserializeOwned>(&self, _vk_digest: &[u32; 8]) -> T {
        self.read_serde()
    }
}
