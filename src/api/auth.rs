use uuid::Uuid;
use crate::api::models::user::UserRole;

#[derive(Clone, Debug)]
pub struct AuthUser {
    pub user_id: Uuid,
    pub role: UserRole,
}

/// Retourne true si `role` a au moins le niveau `min_required`.
/// Exemple: ADMIN passe toutes les vérifications.
pub fn require_role(role: &UserRole, min_required: &UserRole) -> bool {
    use UserRole::*;
    let rank = match role {
        USER => 1,
        ENROLLER => 2,
        ADMIN => 3,
    };
    let min_rank = match min_required {
        USER => 1,
        ENROLLER => 2,
        ADMIN => 3,
    };
    rank >= min_rank
}
