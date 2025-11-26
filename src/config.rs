use std::env;

 
// ↑ On importe le module standard "env" de Rust.
//   Il permet de lire les variables d’environnement (ENV VARS) :
//   - depuis le système (ex: export BINDKEY_PORT=8080)
//   - depuis le fichier .env (grâce à dotenvy)


//Structure représentant la configuration globale du serveur BindKey.
///
/// Pour l'instant, on a :
///   - port : sur quel port HTTP écouter
///   - database_url : URL de connexion PostgreSQL
///
/// Plus tard, on pourra ajouter :
///   - mode debug
///   - secrets JWT
///   - options crypto, etc.
pub struct Config {
    pub port: u16,
    pub database_url: String,
}



impl Config {

    /// Construit une Config à partir des variables d'environnement.
    ///
    /// - charge automatiquement le fichier .env (si présent)
    /// - lit BINDKEY_PORT
    /// - lit DATABASE_URL
    /// - applique une valeur par défaut pour le port si besoin
    /// 
    pub fn from_env() -> Self {

        // ------------------------------------------------------------------
        // 1. Charge automatiquement le fichier `.env` s'il existe.
        // ------------------------------------------------------------------
        //
        // dotenvy::dotenv() lit le fichier .env ET injecte son contenu dans
        // les variables d’environnement du programme.
        //
        // .ok() = on ignore silencieusement l’erreur si le fichier est absent.
        //         (ex : en production on utilise souvent des "vraies" ENV VARS)
        //
        // Exemple du fichier .env :
        //
        //      BINDKEY_PORT=8080
        //      RUST_LOG=info
        //
        dotenvy::dotenv().ok();


        // ------------------------------------------------------------------
        // 2. Lecture de la variable d’environnement "BINDKEY_PORT"
        // ------------------------------------------------------------------
        //
        // env::var(...) retourne un Result<Result<String, VarError>
        // On a trois cas :
        //
        //   - BINDKEY_PORT existe    -> Ok("8080".to_string())
        //   - n’existe pas            -> Err(...)
        //   - existe mais mauvais     -> Ok("trucpasbon")
        //
        // unwrap_or_else → si BINDKEY_PORT n'existe pas,
        //                  alors on utilise la chaîne "8080" par défaut.
        //
        let port = env::var("BINDKEY_PORT")
            .unwrap_or_else(|_| "8080".into())


            // ------------------------------------------------------------------
            // 3. On convertit la chaîne de caractères en u16
            // ------------------------------------------------------------------
            //
            // parse::<u16>() tente de convertir "8080" en un entier.
            // Si ça échoue, panic propre : "BINDKEY_PORT must be a valid u16"
            //
            .parse::<u16>()
            .expect("BINDKEY_PORT must be a valid u16 integer");

        //3) Lecture de l'URL de base de données (DATABASE_URL)
        //
        // Pas de valeur par défaut ici : on considère que c'est OBLIGATOIRE.
        // Si elle n'est pas définie, le serveur panic avec un message clair.

        let database_url= env::var("DATABASE_URL")
        .expect("DATABASE_URL muste be set in .env or environment");

            // ------------------------------------------------------------------
        // 4. Retourne enfin une instance Config
        // ------------------------------------------------------------------
        //
        //    Config { port }
        //
        // Cela permet de faire :
        //    let cfg = Config::from_env();
        //
        Config { port,database_url }
    }
}
