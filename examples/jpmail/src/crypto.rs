
use macros::mcall;
use typing_rules::implicit::InvisibleSideEffectFree;
use typing_rules::lattice::*;

pub struct RSAClosure<L: Label> {
    
    pub plaintext: Labeled<Vec<u8>, L>,            
    
    pub key_id: String,            
}

impl<L: Label> RSAClosure<L> {
    
    pub fn new(plaintext: Labeled<Vec<u8>, L>, key_id: &str) -> Self {
        RSAClosure {
            plaintext,
            key_id: key_id.to_string(),
        }
    }

    pub fn invoke(&self) -> Labeled<Vec<u8>, L> {
        println!(
            "[RSA] Encrypting with public key '{}'",
            self.key_id
        );
        
        self.plaintext.clone()
    }

    pub fn decrypt(ciphertext: Labeled<Vec<u8>, L>, private_key: Labeled<String, L>) -> Labeled<Vec<u8>, L> {
        println!("[RSA] Decrypting using private key (label L)");
        
        let _ = private_key; 
        ciphertext
    }
}

unsafe impl<L: Label> InvisibleSideEffectFree for RSAClosure<L> {}

pub fn aes_encrypt<L: Label>(
    plaintext: Labeled<Vec<u8>, L>,
    _key: Labeled<Vec<u8>, L>,
) -> Labeled<Vec<u8>, L> {
    println!("[AES] Encrypting");
    
    plaintext
}

pub fn aes_decrypt<L: Label>(
    ciphertext: Labeled<Vec<u8>, L>,
    _key: Labeled<Vec<u8>, L>,
) -> Labeled<Vec<u8>, L> {
    println!("[AES] Decrypting");
    ciphertext
}

pub fn des_encrypt<L: Label>(
    plaintext: Labeled<Vec<u8>, L>,
    _key: Labeled<Vec<u8>, L>,
) -> Labeled<Vec<u8>, L> {
    println!("[DES] Encrypting (AES fallback)");
    plaintext
}

pub struct DeclassAuthorization {
    
    pub granted_by: String,        
}

impl DeclassAuthorization {
    pub fn new(principal: impl std::fmt::Display) -> Self {
        DeclassAuthorization {
            granted_by: principal.to_string(),
        }
    }
}

pub fn authorized_declassify<T, L: Label>(
    value: Labeled<T, L>,
    _auth: &DeclassAuthorization,
) -> T {
    declassify(value)
}

pub struct DeclassifyHelper;

impl DeclassifyHelper {
    
    pub fn upgrade_byte_array<Dest: Label>(
        data: Vec<u8>,
    ) -> Labeled<Vec<u8>, Dest> {
        
        Labeled::new(data)
    }

    pub fn declassify_byte_array<Src: Label>(
        data: Labeled<Vec<u8>, Src>,
        auth: DeclassAuthorization,
    ) -> Vec<u8> {
        println!(
            "[DeclassifyHelper] Declassifying (authorized by '{}')",
            auth.granted_by
        );
        
        authorized_declassify(data, &auth)
    }
}
