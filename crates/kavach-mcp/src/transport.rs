//! Stdio transport for MCP message I/O.

use std::io::{self, BufRead, Write};
use std::process::{Child, Command, Stdio};

use crate::protocol::{self, JsonRpcMessage, MAX_MESSAGE_SIZE};

/// A transport for reading/writing line-delimited JSON-RPC messages over stdio.
pub struct McpTransport {
    reader: io::BufReader<Box<dyn io::Read + Send>>,
    writer: Box<dyn io::Write + Send>,
    buffer: String,
}

impl McpTransport {
    /// Create a transport that reads/writes to the given streams.
    pub fn new(reader: Box<dyn io::Read + Send>, writer: Box<dyn io::Write + Send>) -> Self {
        Self {
            reader: io::BufReader::new(reader),
            writer,
            buffer: String::with_capacity(4096),
        }
    }

    /// Spawn an MCP server subprocess and create a transport to it.
    pub fn spawn_server(command: &str, args: &[String]) -> io::Result<(Self, Child)> {
        let mut child = Command::new(command)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "failed to capture stdin"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "failed to capture stdout"))?;

        let transport = Self {
            reader: io::BufReader::new(Box::new(stdout)),
            writer: Box::new(stdin),
            buffer: String::with_capacity(4096),
        };

        Ok((transport, child))
    }

    /// Send a JSON-RPC message.
    pub fn send(&mut self, msg: &JsonRpcMessage) -> Result<(), String> {
        let json =
            protocol::serialize_message(msg).map_err(|e| format!("serialization error: {e}"))?;
        let line = format!("{json}\n");
        self.writer
            .write_all(line.as_bytes())
            .map_err(|e| format!("write error: {e}"))?;
        self.writer
            .flush()
            .map_err(|e| format!("flush error: {e}"))?;
        Ok(())
    }

    /// Send a raw JSON string as a line-delimited message.
    pub fn send_raw(&mut self, json: &str) -> Result<(), String> {
        let line = format!("{json}\n");
        self.writer
            .write_all(line.as_bytes())
            .map_err(|e| format!("write error: {e}"))?;
        self.writer
            .flush()
            .map_err(|e| format!("flush error: {e}"))?;
        Ok(())
    }

    /// Receive a JSON-RPC message (blocking).
    pub fn receive(&mut self) -> Result<JsonRpcMessage, String> {
        self.buffer.clear();
        loop {
            let mut line = String::with_capacity(512);
            let n = self
                .reader
                .read_line(&mut line)
                .map_err(|e| format!("read error: {e}"))?;
            if n == 0 {
                return Err("connection closed".into());
            }
            let trimmed = line.trim().to_string();
            if trimmed.is_empty() {
                continue;
            }
            self.buffer.push_str(&trimmed);
            if self.buffer.len() > MAX_MESSAGE_SIZE {
                return Err("message too large".into());
            }
            // Try to parse; if it fails, keep reading (the message may span multiple lines).
            match protocol::parse_message(&self.buffer) {
                Ok(msg) => {
                    self.buffer.clear();
                    return Ok(msg);
                }
                Err(_) => {
                    continue;
                }
            }
        }
    }
}

/// Helper: send a request and receive the matching response.
pub fn request_response(
    transport: &mut McpTransport,
    msg: &JsonRpcMessage,
) -> Result<JsonRpcMessage, String> {
    transport.send(msg)?;
    transport.receive()
}
