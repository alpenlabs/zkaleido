use std::{error::Error, io, io::Write};

use ciborium::Value;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zkaleido::ZkVmInputError;

const EXIT_CODE_MALFORMED_STDIN: i32 = 10;
const EXIT_CODE_ZKVM_INP: i32 = 20;
const EXIT_CODE_IO: i32 = 30;

pub type ProcResult<T> = Result<T, ProcError>;

#[derive(Debug, Error)]
pub enum ProcError {
    #[error("malformed stdin buf")]
    MalformedStdin,

    #[error("zkvm input: {0}")]
    ZkVmInput(#[from] ZkVmInputError),

    #[error("io: {0}")]
    Io(#[from] io::Error),
}

impl ProcError {
    /// Returns the exit code the process should have when we exit.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::MalformedStdin => EXIT_CODE_MALFORMED_STDIN,
            Self::ZkVmInput(_) => EXIT_CODE_ZKVM_INP,
            Self::Io(_) => EXIT_CODE_IO,
        }
    }

    fn get_extra(&self) -> Option<Value> {
        match self {
            // TODO(trey): make this put something here
            Self::MalformedStdin => None,

            // TODO(trey): make this put something here
            Self::ZkVmInput(_) => None,
            Self::Io(error) => {
                let io_ex = IoErrorExtra {
                    raw_os_err: error.raw_os_error(),
                    kind_str: format!("{}", error.kind()),
                    description: error.get_ref().map(|e| e.to_string()),
                };

                Some(Value::serialized(&io_ex).expect("host: serialize io error data"))
            }
        }
    }
}

/// Extra data provided by IO errors.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IoErrorExtra {
    raw_os_err: Option<i32>,
    kind_str: String,
    description: Option<String>,
}

impl IoErrorExtra {
    pub fn raw_os_err(&self) -> Option<i32> {
        self.raw_os_err
    }

    pub fn kind_str(&self) -> &str {
        &self.kind_str
    }
}

/// Stdout schema when we exit with an error.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ErrorOutput {
    /// Restating the error code, for convenience.
    code: i32,

    /// Nicely formatted error message.
    message: String,

    /// Raw `Debug`-printed error message.
    raw: String,

    /// Extra machine-readable data supplied by the error, if any.
    extra: Value,
}

impl ErrorOutput {
    /// Generates an error message from a proc error.
    ///
    /// # Panics
    ///
    /// If there's an error serializing messages.
    pub fn from_error(e: &ProcError) -> Self {
        Self {
            code: e.exit_code(),
            message: format!("{e}"),
            raw: format!("{e:?}"),
            extra: e
                .get_extra()
                .expect("host: serialize error extra")
                .ok_or(Value::Null),
        }
    }

    pub fn code(&self) -> i32 {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }

    pub fn extra(&self) -> &Value {
        &self.extra
    }

    /// Writes the output to a writer.
    pub fn write_to_writer(&self, w: &mut impl Write) {
        ciborium::into_writer(self, w).expect("host: write error output");
    }
}
