# bindkey-server
BindKey - Master Project - Server Code Repository

## 🚀 Prérequis

- Docker + Docker Compose
- Rust (si vous voulez lancer en mode dev)

## 🗄️ 1. Lancer la base PostgreSQL (Docker)

Dans le dossier du projet :

```bash
docker compose up -d

route sessions/login envoyer juste caractere aléatoire pour la cle  verifiaction , garder le string genere en memoire pour la verification GOOD 
route sessions/verify : objectif verifier que c'est la bonne bindkey , verifier signature clé bindkey avec la clé public stocké bdd , si ok (le string aléatoire envoyer==dechifrement avec la clé public du bindkey ) envoyer token de session definitive pour faire les routes , nom user + roles , pour etre sur que c'est bien la meme personne avec le string on recoit le email de la personne GOOD 



mdp stockage : 
-argon 2 avec hash+salt
-chiffrer le mdp avec AES (clé symetrique doit pas etre stocké dans la BDD)
-stocker la clé symetrique dans un secret kubernetes et/ou dans parametres d'environnement 
GOOD 

sudo -E kubectl port-forward --address 0.0.0.0 -n ingress-nginx service/ingress-nginx-controller 443:443
# Si tu utilises l'Ingress Nginx standard
kubectl logs -f -l app.kubernetes.io/name=ingress-nginx -n ingress-nginx

kubectl exec -it bindkey-deployment-85d87f9556-j4fzn -c bindkey-db -- psql -U admin_bindkey -d bindkey

la signature sans le préfixe 0x, juste les caractères de 0-9 et A-F
