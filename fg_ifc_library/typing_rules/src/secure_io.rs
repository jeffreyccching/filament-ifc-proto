//! IFC-aware I/O wrappers for the standard library.
//!
//! A handle at label `L` mediates one external boundary in both directions:
//!
//! - **writes** require `Src: LEQ<L>` — no write-down;
//! - **reads** return `Labeled<_, L>` — data from an `L` source carries `L`,
//!   guaranteed by the signature rather than by the caller remembering to
//!   wrap the call in `mcall!`.
//!
//! Handles are *not* wrapped in `Labeled`: the handle type already carries
//! `L` in its own `PhantomData<L>`, so methods are called directly and no
//! unchecked `mcall!` is involved.
//!
//! - [`SecureFile`] — wraps `std::fs` (read/write files)
//! - [`SecureStream`] — wraps `std::net::TcpStream` (network I/O)
//! - [`SecureCommand`] — wraps `std::process::Command` (subprocess I/O)
//! - [`secure_print`] / [`secure_eprint`] — wraps stdout/stderr output

use crate::lattice::{Label, Labeled, LEQ};
use std::marker::PhantomData;
use std::path::PathBuf;

/// A file handle labeled with security level `L`.
///
/// Wraps `std::fs` free functions (`read_to_string`, `read`, `write`)
/// with LEQ enforcement on writes.
pub struct SecureFile<L: Label> {
    path: PathBuf,
    _label: PhantomData<L>,
}

impl<L: Label> SecureFile<L> {
    /// Create a labeled file handle.
    pub fn open(path: PathBuf) -> Self {
        SecureFile { path, _label: PhantomData }
    }

    /// Wraps `std::fs::read_to_string`. The contents of an `L`-labeled file
    /// are `L`-labeled.
    pub fn read_to_string(&self) -> std::io::Result<Labeled<String, L>> {
        std::fs::read_to_string(&self.path).map(Labeled::new)
    }

    /// Wraps `std::fs::read`. The contents of an `L`-labeled file are
    /// `L`-labeled.
    pub fn read(&self) -> std::io::Result<Labeled<Vec<u8>, L>> {
        std::fs::read(&self.path).map(Labeled::new)
    }

    /// Wraps `std::fs::write` with `Src: LEQ<L>` (no-write-down).
    pub fn write<Src: Label + LEQ<L>>(&self, data: &Labeled<String, Src>) -> std::io::Result<()> {
        std::fs::write(&self.path, data.declassify_ref())
    }

    /// Wraps `std::fs::write` for byte data with `Src: LEQ<L>`.
    pub fn write_bytes<Src: Label + LEQ<L>>(&self, data: &Labeled<Vec<u8>, Src>) -> std::io::Result<()> {
        std::fs::write(&self.path, data.declassify_ref())
    }
}

// =========================================================================
// SecureStream — to handle TCP network I/O with labeled streams
// =========================================================================

/// A TCP stream labeled with security level `L`.
///
/// Wraps `std::net::TcpStream` with LEQ enforcement on writes.
pub struct SecureStream<L: Label> {
    stream: std::net::TcpStream,
    _label: PhantomData<L>,
}

impl<L: Label> SecureStream<L> {
    /// Wraps `TcpStream::connect`.
    pub fn connect(addr: &str) -> std::io::Result<Self> {
        let stream = std::net::TcpStream::connect(addr)?;
        Ok(SecureStream { stream, _label: PhantomData })
    }

    /// Reads at most `max` bytes, `L`-labeled.
    ///
    /// There is deliberately no `read(&mut self, buf: &mut [u8])`: filling a
    /// caller-supplied unlabeled buffer would put data from an `L` stream into
    /// raw memory, and the label would land on the returned count rather than
    /// on the bytes. Returning the buffer is the only sound shape.
    pub fn read_bytes(&mut self, max: usize) -> std::io::Result<Labeled<Vec<u8>, L>> {
        use std::io::Read;
        let mut buf = vec![0u8; max];
        let n = self.stream.read(&mut buf)?;
        buf.truncate(n);
        Ok(Labeled::new(buf))
    }

    /// Wraps `std::io::read_to_string` on the stream; the result is `L`-labeled.
    pub fn read_to_string(&mut self) -> std::io::Result<Labeled<String, L>> {
        use std::io::Read;
        let mut s = String::new();
        self.stream.read_to_string(&mut s)?;
        Ok(Labeled::new(s))
    }

    /// Wraps `TcpStream::write_all` with `Src: LEQ<L>` (no-write-down).
    pub fn write<Src: Label + LEQ<L>>(&mut self, data: &Labeled<String, Src>) -> std::io::Result<()> {
        use std::io::Write;
        self.stream.write_all(data.declassify_ref().as_bytes())
    }

    /// Wraps `TcpStream::write_all` for byte data with `Src: LEQ<L>`.
    pub fn write_bytes<Src: Label + LEQ<L>>(&mut self, data: &Labeled<Vec<u8>, Src>) -> std::io::Result<()> {
        use std::io::Write;
        self.stream.write_all(data.declassify_ref())
    }
}

// =========================================================================
// SecureCommand — to handle subprocess I/O with labeled commands and arguments
// =========================================================================

/// A process command labeled with security level `L`.
///
/// Wraps `std::process::Command`. Arguments carrying labeled data
/// must satisfy `Src: LEQ<L>` — prevents exfiltrating secrets
/// via subprocess arguments or stdin.
pub struct SecureCommand<L: Label> {
    cmd: std::process::Command,
    _label: PhantomData<L>,
}

impl<L: Label> SecureCommand<L> {
    /// Wraps `Command::new`.
    pub fn new(program: &str) -> Self {
        SecureCommand {
            cmd: std::process::Command::new(program),
            _label: PhantomData,
        }
    }

    /// Wraps `Command::arg` with `Src: LEQ<L>`.
    pub fn arg<Src: Label + LEQ<L>>(&mut self, arg: &Labeled<String, Src>) -> &mut Self {
        self.cmd.arg(arg.declassify_ref());
        self
    }

    /// Add a public (unlabeled) argument.
    pub fn arg_public(&mut self, arg: &str) -> &mut Self {
        self.cmd.arg(arg);
        self
    }

    /// Wraps `Command::output`. The process was fed `LEQ<L>`-checked
    /// arguments, so its output is `L`-labeled.
    pub fn output(&mut self) -> std::io::Result<Labeled<std::process::Output, L>> {
        self.cmd.output().map(Labeled::new)
    }

    /// Wraps `Command::status`.
    pub fn status(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.cmd.status()
    }
}

// =========================================================================
// Stdout / Stderr — labeled console output
// =========================================================================

/// Write labeled data to stdout. Requires `Src: LEQ<Public>` —
/// only public data can be printed to the console.
pub fn secure_print<Src: Label + LEQ<crate::lattice::Public>>(data: &Labeled<String, Src>) {
    print!("{}", data.declassify_ref());
}

/// Write labeled data to stdout with newline. Requires `Src: LEQ<Public>`.
pub fn secure_println<Src: Label + LEQ<crate::lattice::Public>>(data: &Labeled<String, Src>) {
    println!("{}", data.declassify_ref());
}

/// Write labeled data to stderr. Requires `Src: LEQ<Public>`.
pub fn secure_eprintln<Src: Label + LEQ<crate::lattice::Public>>(data: &Labeled<String, Src>) {
    eprintln!("{}", data.declassify_ref());
}
