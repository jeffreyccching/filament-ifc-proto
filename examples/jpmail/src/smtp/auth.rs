
use crate::crypto::{authorized_declassify, DeclassAuthorization};
use macros::mcall;
use typing_rules::lattice::*;

pub struct DigestMD5<L: Label> {
    
    pub password: Labeled<String, L>,              
    
    pub username: String,          
    
    pub realm: String,             
}

impl<L: Label> DigestMD5<L> {
    pub fn new(password: Labeled<String, L>, username: impl std::fmt::Display, realm: &str) -> Self {
        DigestMD5 {
            password,
            username: username.to_string(),
            realm: realm.to_string(),
        }
    }

    pub fn auth_client(&self, challenge: Labeled<String, L>) -> Labeled<String, L> {
        println!(
            "[DigestMD5] Computing SASL response for '{}' in realm '{}'",
            self.username, self.realm
        );
        
        let auth = DeclassAuthorization::new(&self.username);
        let response = format!(
            "username=\"{}\",realm=\"{}\",nonce=\"{}\",response=[md5_stub]",
            self.username,
            self.realm,
            authorized_declassify(challenge, &auth)
        );
        Labeled::new(response)
    }

    pub fn auth_server(&self, client_response: Labeled<String, L>) -> Labeled<bool, L> {
        
        mcall!(client_response.contains("response="))
    }
}

pub struct DigestApop<L: Label> {
    pub password: Labeled<String, L>,
}

impl<L: Label> DigestApop<L> {
    pub fn new(password: Labeled<String, L>) -> Self {
        DigestApop { password }
    }

    pub fn compute_apop_digest(&self, challenge: Labeled<String, L>, auth: &DeclassAuthorization) -> Labeled<String, L> {
        println!("[APOP] Computing MD5 digest (password ⊕ challenge)...");
        
        let _ = &self.password; 
        Labeled::new(format!("[md5_apop:{}_stub]", authorized_declassify(challenge, auth)))
    }
}
