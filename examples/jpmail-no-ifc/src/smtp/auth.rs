
pub struct DigestMD5 {
    
    pub password: String,
    
    pub username: String,
    
    pub realm: String,
}

impl DigestMD5 {
    pub fn new(password: String, username: impl std::fmt::Display, realm: &str) -> Self {
        DigestMD5 {
            password,
            username: username.to_string(),
            realm: realm.to_string(),
        }
    }

    pub fn auth_client(&self, challenge: String) -> String {
        println!(
            "[DigestMD5] Computing SASL response for '{}' in realm '{}'",
            self.username, self.realm
        );
        
        format!(
            "username=\"{}\",realm=\"{}\",nonce=\"{}\",response=[md5_stub]",
            self.username,
            self.realm,
            challenge
        )
    }

    pub fn auth_server(&self, client_response: String) -> bool {
        
        client_response.contains("response=")
    }
}

pub struct DigestApop {
    pub password: String,
}

impl DigestApop {
    pub fn new(password: String) -> Self {
        DigestApop { password }
    }

    pub fn compute_apop_digest(&self, challenge: String) -> String {
        println!("[APOP] Computing MD5 digest (password + challenge)...");
        
        let _ = &self.password; 
        format!("[md5_apop:{}_stub]", challenge)
    }
}
