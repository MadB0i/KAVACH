//! KAVACH MCP security adapter.
//!
//! Proxies MCP (Model Context Protocol) tool calls through KavachRuntime
//! for policy evaluation, enforcement, and audit.

#![doc(html_root_url = "https://github.com/anomalyco/kavach")]

pub mod protocol;
pub mod proxy;
pub mod transport;
