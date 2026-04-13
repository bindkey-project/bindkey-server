# bindkey-server
BindKey - Master Project - Server Code Repository

## 🚀 Prérequis

- Docker + Docker Compose
- Rust (si vous voulez lancer en mode dev)

## 🗄️ 1. Lancer la base PostgreSQL (Docker)

Dans le dossier du projet :

docker compose up -d

sudo -E kubectl port-forward --address 0.0.0.0 -n ingress-nginx service/ingress-nginx-controller 443:443
# Si tu utilises l'Ingress Nginx standard
kubectl logs -f -l app.kubernetes.io/name=ingress-nginx -n ingress-nginx

kubectl exec -it bindkey-deployment-85d87f9556-j4fzn -c bindkey-db -- psql -U admin_bindkey -d bindkey
kubectl exec -it bindkey-db-1 -c postgres -- psql -U postgres -d bindkey

bindkey=# INSERT INTO users (
    id, 
    first_name, 
    last_name, 
    email, 
    role, 
    status, 
    recovery_code_hash, 
    password_hash
) VALUES (
    '550e8400-e29b-41d4-a716-446655440000', 
    'Admin', 
    'BindKey', 
    'admin@bindkey.local', 
    'ADMIN', 
    'ACTIVE', 
    'recovery_dummy_hash', 
    'DQutzqetJxk4qAPb/Pb/S3saLW8rOI+DRh5KfJWsCZ3nJ1hnHVMH2MZ724khOdvN9xaD0jmtCWOuf2dK9nxk0r0S4zmDpM3NfqIRIh3lGHx0hmweArh+zegi6RbPNccrjKrNP5JM27NP0wtvACkOaAaZ2JbkcKboVUecmMM='
);
INSERT 0 1
bindkey=# INSERT INTO bindkeys (
    id, 
    user_id, 
    bindkey_uid, 
    fingerprint_template, 
    public_key, 
    status
) VALUES (
    '660f9511-f30c-52e5-b827-557766551111', 
    '550e8400-e29b-41d4-a716-446655440000', 
    'BK-ADMIN-001', 
    'template_data_biometric', 
    'ecdsa_public_key_content', 
    'ACTIVE'
);


la signature sans le préfixe 0x, juste les caractères de 0-9 et A-F


Route lister toutes les bindkeys en tant que ADMIN seulemement -> bindkeys/all voir l'ID + à qui elle appartient + son status
Route pour supprimer BINDKEY -> bindkeys/delete/:id (modifier le statut),on recoit le nouveau etat de la bindkey 
Route pour verifier si le nom du volume que tu m'envoie existe déjà -> volumes/verify , si oui envoyer ID volume , si non envoyer non 



