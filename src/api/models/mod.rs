// Modèle représentant la table `users`
pub mod user;

// Modèle représentant la table `devices` (périphériques enregistrés)
pub mod device;

// Modèle pour la table `bindkeys` (clés d’accès ou identifiants)
pub mod bindkey;

// Modèle pour la table `disks` (disques attachés aux machines)
pub mod disk;

// Modèle pour la table `volumes` (espaces de stockage logiques)
pub mod volume;

// Modèle pour la table `volume_permissions` (droits d’accès aux volumes)
pub mod volume_permission;

// Modèle pour la table `bindkey_reset` (historique des réinitialisations)
pub mod bindkey_reset;

// Modèle pour la table `sessions` (connexions utilisateurs / logs)
pub mod session;

// Modèle pour la table `audit_log` (journalisation sécurisée)
pub mod audit_log;

pub mod mounted_volume;
