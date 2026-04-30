// ─────────────────────────────────────────────────────────────
// Déclaration des sous-modules de routes
// ─────────────────────────────────────────────────────────────
//
// Chaque module regroupe un ensemble cohérent de routes API
// (Users, BindKeys, Disks, Volumes, Sessions, etc.)
// Cette organisation améliore la lisibilité et la maintenabilité
//

// Routes liées aux utilisateurs (création, recherche, statut)
mod user_routes_module;

// Routes liées aux BindKeys (enrôlement, statut, reset)
pub mod bindkey_routes;

// ─────────────────────────────────────────────────────────────
// Ré-export des fonctions de construction de routeurs
// ─────────────────────────────────────────────────────────────
//
// pub use permet d’exposer directement les fonctions
// depuis crate::api::routes::...
//

pub use bindkey_routes::bindkey_routes;
pub use user_routes_module::user_routes;

// Routes liées aux volumes chiffrés
pub mod volume_routes;

// Routes de partage et permissions
pub mod permission_routes;

// Routes de gestion des sessions (login / refresh / logout)
pub mod session_routes;

// Routes de traçabilité des montages / démontages
pub mod mount_routes;

// ─────────────────────────────────────────────────────────────
// Ré-export des routeurs spécialisés
// ─────────────────────────────────────────────────────────────

pub use mount_routes::mount_routes;
pub use permission_routes::permission_routes;
pub use session_routes::session_routes;
pub use volume_routes::volume_routes;
