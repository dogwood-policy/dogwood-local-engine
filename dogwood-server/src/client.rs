//! Clients for the two sockets: [`DataClient`] and [`ControlClient`].
//!
//! These back the CLI's subcommands and the end-to-end tests, and they are the
//! reference for what a third-party client must do — the protocol is plain
//! length-prefixed JSON over a Unix socket precisely so that speaking it needs no
//! generated bindings, but having a correct implementation in-tree keeps the
//! server honest about its own contract.
//!
//! The two clients are separate types for the same reason the sockets are
//! separate: a [`DataClient`] has no method that could mutate
//! policy, so code holding one cannot accidentally be granted authoring reach.

use std::os::unix::net::UnixStream;
use std::path::Path;

use crate::protocol::{
    ControlRequest, ControlResponse, DataRequest, DataResponse, read_frame, write_frame,
};

/// A client for the data socket: submit events, get verdicts.
pub struct DataClient {
    stream: UnixStream,
}

impl DataClient {
    /// Connect to the data socket at `path`.
    pub fn connect(path: impl AsRef<Path>) -> Result<Self, String> {
        let stream = UnixStream::connect(path.as_ref())
            .map_err(|e| format!("connect {}: {e}", path.as_ref().display()))?;
        Ok(DataClient { stream })
    }

    /// Send one request and read its response.
    pub fn call(&mut self, request: &DataRequest) -> Result<DataResponse, String> {
        write_frame(&mut self.stream, request).map_err(|e| e.to_string())?;
        read_frame(&mut self.stream).map_err(|e| e.to_string())
    }
}

/// A client for the control socket: install policy, read status, checkpoint.
pub struct ControlClient {
    stream: UnixStream,
}

impl ControlClient {
    /// Connect to the control socket at `path`.
    ///
    /// A connection refused with `EACCES` here is the socket's `0700` mode doing
    /// its job — the caller's uid is not the owner,
    /// so the message says so rather than reporting a bare errno.
    pub fn connect(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        let stream = UnixStream::connect(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                format!(
                    "connect {}: permission denied — the control socket is \
                     owner-only; run as the user that owns the server",
                    path.display()
                )
            } else {
                format!("connect {}: {e}", path.display())
            }
        })?;
        Ok(ControlClient { stream })
    }

    /// Send one request and read its response.
    pub fn call(&mut self, request: &ControlRequest) -> Result<ControlResponse, String> {
        write_frame(&mut self.stream, request).map_err(|e| e.to_string())?;
        read_frame(&mut self.stream).map_err(|e| e.to_string())
    }
}
