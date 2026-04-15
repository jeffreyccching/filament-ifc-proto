
use typing_rules::lattice::*;

pub struct Password<L: Label> {
    
    pub encrypted_file: String,    
    
    pub iv_file: String,           
    
    pub key_file: String,          
    
    _label: std::marker::PhantomData<L>,
}

impl<L: Label> Password<L> {
    
    pub fn new(base_path: &str) -> Self {
        Password {
            encrypted_file: format!("{}password", base_path),
            iv_file: format!("{}password_iv", base_path),
            key_file: format!("{}password_key", base_path),
            _label: std::marker::PhantomData,
        }
    }

    pub fn get_password(&self) -> Labeled<String, L> {
        println!(
            "[Password] Reading encrypted credential from '{}'",
            self.encrypted_file
        );
        
        Labeled::new(format!("[decrypted_from:{}]", self.encrypted_file))
    }

    pub fn set_password(&self, pwd: Labeled<String, L>) {
        println!(
            "[Password] Storing encrypted credential to '{}'",
            self.encrypted_file
        );
        
        drop(pwd);
    }

    pub fn to_base64(data: &[u8]) -> String {
        
        format!("[base64:{}bytes]", data.len())
    }
}

pub struct NewPassword;

impl NewPassword {
    
    pub fn bootstrap<L: Label>(username: &str, plaintext: Labeled<String, L>) {
        println!(
            "[NewPassword] Bootstrapping encrypted credential for principal '{}'",
            username
        );
        println!(
            "[NewPassword] Verifying delegation: 'me actsFor {}' ...",
            username
        );
        
        let pw = Password::<L>::new(&format!("demo/passwd-{}/", username));
        pw.set_password(plaintext);
        println!("[NewPassword] Done — password file written.");
    }
}
