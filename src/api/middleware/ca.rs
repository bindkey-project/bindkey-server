use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose};

pub fn generate_root_ca() -> (String, String) {
    // 1. Définir les paramètres du certificat
    let mut params = CertificateParams::default();
    
    // On donne un nom à notre autorité
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "BindKey Root Authority");
    dn.push(DnType::OrganizationName, "BindKey Security");
    params.distinguished_name = dn;

    // 2. IMPORTANT : Déclarer que c'est une CA (Autorité de Certification)
    // Cela permet à ce certificat de signer d'autres certificats.
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    
    // 3. Définir les usages (Signer des certificats et des listes de révocation)
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];

    // 4. Générer la paire de clés (Ed25519 par défaut dans rcgen)
    let key_pair = KeyPair::generate().unwrap();
    
    // 5. Créer le certificat auto-signé
    let cert = params.self_signed(&key_pair).unwrap();

    // Retourne (Certificat PEM, Clé Privée PEM)
    (cert.pem(), key_pair.serialize_pem())
}