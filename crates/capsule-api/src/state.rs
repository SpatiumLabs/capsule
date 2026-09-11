//! Shared application state types exposed to API handlers.

use std::sync::Arc;

use capsule_core::SandboxFacade;

/// App state is one shared trait object. All handlers depend on this core
/// contract, not on any concrete host agent, so unit tests can substitute a
/// mock and the API crate never imports host-only control operations.
pub(crate) type AppState = Arc<dyn SandboxFacade>;
