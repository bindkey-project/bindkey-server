// Ce fichier déclare tous les sous-modules du dossier models.
// Chaque `pub mod xyz;` correspond à un fichier `xyz.rs` dans le même dossier.
//
// L'objectif est que toutes les structs de ton backend BindKey
// soient accessibles via :
// 
//     use crate::models::User;
//     use crate::models::BindKey;
//     use crate::models::Volume;
//
// C'est une architecture propre, claire, scalable.

pub mod user;
pub mod bindkey;
pub mod disk;
pub mod volume;
pub mod volume_permission;
pub mod session;
pub mod mounted_volume;
pub mod bindkey_reset;
pub mod audit_log;

// Optionnel : tu peux aussi réexporter des types si tu veux raccourcir les imports.
// Exemple :
// pub use user::User;
// pub use bindkey::BindKey;
