#![forbid(unsafe_code)]

mod auth;
mod error;
mod middleware;
mod routes;
mod server;
pub mod state;
pub mod types;

pub use auth::GatewayToken;
pub use error::{GatewayError, KavachErrorCode};
pub use server::GatewayBuilder;
pub use state::GatewayConfig;

#[cfg(test)]
mod tests;
