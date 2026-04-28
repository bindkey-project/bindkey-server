use rcgen::{
    CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose, RemoteKeyPair, SignatureAlgorithm, PKCS_ECDSA_P256_SHA256,
    Error as RcgenError,
};
use time::{Duration, OffsetDateTime};
use base64::Engine;

pub fn generate_root_ca() -> (String, String) {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "BindKey Root Authority");
    dn.push(DnType::OrganizationName, "BindKey Security");
    params.distinguished_name = dn;

    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];

    let key_pair = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();

    (cert.pem(), key_pair.serialize_pem())
}

/// Charge la Root CA depuis ses PEM et reconstruit le Certificate signataire.
fn load_root_ca(root_cert_pem: &str, root_key_pem: &str) -> Result<(rcgen::Certificate, KeyPair), String> {
    let root_key_pair = KeyPair::from_pem(root_key_pem)
        .map_err(|e| format!("Erreur clé Root CA: {e}"))?;
    let root_params = CertificateParams::from_ca_cert_pem(root_cert_pem)
        .map_err(|e| format!("Erreur params Root CA: {e}"))?;
    let root_cert = root_params
        .self_signed(&root_key_pair)
        .map_err(|e| format!("Erreur reconstruction Root CA: {e}"))?;
    Ok((root_cert, root_key_pair))
}

// ─────────────────────────────────────────────────────────────
// RemoteKeyPair pour une clé publique BindKey
// ─────────────────────────────────────────────────────────────
//
// rcgen accepte un signataire "distant" via le trait RemoteKeyPair.
// Il utilise UNIQUEMENT public_key() + algorithm() pour le SUBJECT
// (la clé privée n'est jamais touchée).
// La méthode sign() n'est jamais appelée pour le subject_key dans signed_by.
//
struct BindkeyRemotePublicKey {
    /// Point P-256 non compressé : 0x04 || X || Y (65 octets)
    raw_uncompressed: Vec<u8>,
}

impl RemoteKeyPair for BindkeyRemotePublicKey {
    fn public_key(&self) -> &[u8] {
        &self.raw_uncompressed
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ECDSA_P256_SHA256
    }

    fn sign(&self, _msg: &[u8]) -> Result<Vec<u8>, RcgenError> {
        // Jamais appelé : pour le subject_key, rcgen n'utilise que public_key() + algorithm().
        // La signature est faite par l'issuer (Root CA), pas par le subject.
        Err(RcgenError::RemoteKeyError)
    }
}

/// Décode une clé publique P-256 fournie en hex ou base64,
/// et retourne le format non compressé (65 octets) attendu par rcgen.
fn decode_public_key(public_key_str: &str) -> Result<Vec<u8>, String> {
    let trimmed = public_key_str.trim();

    // Tente hex d'abord, puis base64
    let bytes = hex::decode(trimmed).or_else(|_| {
        base64::engine::general_purpose::STANDARD
            .decode(trimmed)
            .map_err(|e| format!("Décodage clé publique (ni hex ni base64): {e}"))
    })?;

    let point = p256::EncodedPoint::from_bytes(&bytes)
        .map_err(|e| format!("Point EC P-256 invalide: {e}"))?;

    // Si la clé est compressée (33 octets), on la décompresse
    if point.is_compressed() {
        let verifying = p256::ecdsa::VerifyingKey::from_encoded_point(&point)
            .map_err(|e| format!("VerifyingKey invalide: {e}"))?;
        Ok(verifying.to_encoded_point(false).as_bytes().to_vec())
    } else {
        Ok(point.as_bytes().to_vec())
    }
}

/// Génère un certificat X.509 pour une BindKey, en utilisant SA propre clé publique
/// (déjà stockée en base lors de l'enrôlement).
///
/// La clé privée de la BindKey ne quitte JAMAIS le device.
/// Le serveur ne reçoit/ne stocke que la clé publique.
///
/// Retourne uniquement le certificate PEM.
pub fn generate_bindkey_certificate(
    root_cert_pem: &str,
    root_key_pem: &str,
    bindkey_public_key: &str,
    bindkey_id: &str,
    user_id: &str,
) -> Result<String, String> {
    // 1. Décode la clé publique de la BindKey (hex/base64 → bytes uncompressed)
    let raw_uncompressed = decode_public_key(bindkey_public_key)?;

    // 2. Wrap dans un RemoteKeyPair
    let remote = Box::new(BindkeyRemotePublicKey { raw_uncompressed });
    let subject_key = KeyPair::from_remote(remote)
        .map_err(|e| format!("Erreur création KeyPair distant: {e}"))?;

    // 3. Charge la Root CA (signataire)
    let (root_cert, root_key_pair) = load_root_ca(root_cert_pem, root_key_pem)?;

    // 4. Construit les paramètres du certificat
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, format!("BindKey-{}", bindkey_id));
    dn.push(DnType::OrganizationName, "BindKey Security");
    dn.push(DnType::OrganizationalUnitName, format!("User-{}", user_id));

    let mut params = CertificateParams::new(vec![format!("bindkey-{}", bindkey_id)])
        .map_err(|e| format!("Erreur init params certificat: {e}"))?;

    params.distinguished_name = dn;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];

    // Validité : 2 ans
    params.not_before = OffsetDateTime::now_utc();
    params.not_after = OffsetDateTime::now_utc() + Duration::days(730);

    // 5. Signature par la Root CA (la BindKey n'est PAS appelée à signer)
    let cert = params
        .signed_by(&subject_key, &root_cert, &root_key_pair)
        .map_err(|e| format!("Erreur signature certificat: {e}"))?;

    Ok(cert.pem())
}
