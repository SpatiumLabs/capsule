//! Library surface for the Capsule platform API.

mod auth;
mod config;
mod error;
mod handlers;
mod middleware;
mod policy_enforcer;
mod routes;
mod state;

pub use config::*;
pub use error::*;
pub use policy_enforcer::*;
pub use routes::build_router;
