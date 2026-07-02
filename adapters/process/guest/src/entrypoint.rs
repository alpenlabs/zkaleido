use std::{
    collections::VecDeque,
    io::{self, Cursor, Read, Write},
    process,
};

use zkaleido::ZkVmProgram;

use crate::{env::*, errors::*};

/// Main entrypoint for process-like program runners.
///
/// Handles processing input and exiting on error conditions.
pub fn entrypoint<P: ZkVmProgram>() {
    match entrypoint_inner::<P>() {
        Ok(v) => {
            // TODO(trey): emit output
        }
        Err(e) => handle_error(e),
    }
}

fn entrypoint_inner<P: ZkVmProgram>() -> ProcResult<Vec<Vec<u8>>> {
    let inp_bufs = read_input_bufs()?;
    let inp_buf_queue = VecDeque::from(inp_bufs);
    let env = ProcessZkVmEnv::new(EnvState::new(inp_buf_queue));

    // TODO(trey): execute the program

    Ok(env.into_state().into_outputs())
}

fn read_input_bufs() -> ProcResult<Vec<Vec<u8>>> {
    let mut stdin = io::stdin().lock();

    let mut full_stdin_buf = Vec::new();
    let cnt = stdin.read_to_end(&mut full_stdin_buf)?;

    // TODO(trey): make this use u32 length prefixes, read until end
    let mut cur = Cursor::new(full_stdin_buf);
    let inp_bufs = ciborium::from_reader(&mut cur).map_err(|_| ProcError::MalformedStdin)?;

    // Also check that we consumed all the bytes.
    if cur.position() != cnt as u64 {
        return Err(ProcError::MalformedStdin);
    }

    Ok(inp_bufs)
}

fn handle_real_output<P: ZkVmProgram>(prog_output: P::Output) {
    // Exit with a real exit code.
    process::exit(0);
}

/// Handles a process error by writing the error data to stdout and exiting with
/// the appropriate non-zero exit code.
fn handle_error(e: ProcError) {
    // Sanity check to force a nonzero exit code.
    let exit_code = e.exit_code();
    assert_ne!(exit_code, 0, "host: exit code must be nonzero");

    // Generate the error report and write it.
    let err_outp = ErrorOutput::from_error(&e);
    let mut stdout = io::stdout().lock();
    err_outp.write_to_writer(&mut stdout);

    process::exit(exit_code);
}
