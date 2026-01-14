use serde::{Serialize, Deserialize};
use sqlx::FromRow;
use uuid::Uuid;
use chrono::{DateTime, Utc};


/// Représente une session d'accès créée après une authentification BindKey.
///
/// Une session est un "contrat temporaire" entre :
///   - un utilisateur (user_id)
///   - une BindKey spécifique (bindkey_id)
///   - le soft BindKey sur la machine
///
/// Tant que la session n'est pas expirée, le client peut faire :
///   - des actions non sensibles (listage, lecture de métadonnées) via server_token
/// Pour une action sensible (ex : monter un volume),
/// le serveur redemande une preuve cryptographique (challenge + signature).

#[derive(Debug,Serialize,Deserialize,FromRow)]


pub struct session{
    pub id: Uuid,
    pub user_id: Uuid,

    /// BindKey utilisée pour ouvrir cette session.
    /// ON DELETE CASCADE : si on supprime la BindKey, ses sessions disparaissent.
    pub bindkey_id: Uuid,

    /// Token côté serveur :
    /// - envoyé dans les requêtes HTTP (Authorization header)
    /// - permet au serveur d'identifier rapidement la session
    ///
    /// ⚠️ Important : ce token ne doit pas suffire pour une action sensible.
    pub server_token: String,

    /// Token côté client (soft / machine) :
    /// - sert à renforcer la session localement
    /// - peut être utilisé pour vérifier qu’on est bien sur "le bon client"
    ///
    /// ⚠️ Ce token n'est pas un secret ultra-fort non plus :
    /// la sécurité forte vient de la signature BindKey.
    pub local_token: String,


    /// Date d'expiration de la session.
    /// Quand expires_at < now(), il faut refaire l'authentification.
    pub expires_at: DateTime<Utc>,

    pub created_at: DateTime<Utc>,
}