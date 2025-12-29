mod user_routes_module;
pub mod bindkey_routes;

pub use user_routes_module::user_routes;
pub use bindkey_routes::bindkey_routes; // ré-export de la fonction
