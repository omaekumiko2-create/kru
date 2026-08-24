pub mod api_catalog;
pub mod backup;
pub mod browser;
pub mod crypto;
pub mod executor;
pub mod mcp;
pub mod model;
pub mod policy;
pub mod terminal;
pub mod vault;

#[cfg(feature = "gui")]
pub mod agent_registry;
#[cfg(feature = "gui")]
pub mod commands;
#[cfg(feature = "desktop-fill")]
pub mod desktop;
#[cfg(not(feature = "desktop-fill"))]
#[path = "desktop_headless.rs"]
pub mod desktop;

#[cfg(feature = "gui")]
pub use commands::run_gui;
