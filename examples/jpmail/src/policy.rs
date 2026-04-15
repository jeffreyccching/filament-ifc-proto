
use std::collections::HashMap;
use std::marker::PhantomData;
use typing_rules::implicit::InvisibleSideEffectFree;
use typing_rules::lattice::*;

#[derive(Clone)]
pub struct PrincipalWrapper<L: Label> {
    
    pub name: String, 
    
    pub keystore_path: String, 
    
    pub cert_path: String, 
    _label: PhantomData<L>,
}

impl<L: Label> PrincipalWrapper<L> {
    
    pub fn new(name: impl std::fmt::Display, cert_dir: impl std::fmt::Display) -> Self {
        PrincipalWrapper {
            name: name.to_string(),
            keystore_path: format!("{}{}.keystore", cert_dir, name),
            cert_path: format!("{}cacert.pem", cert_dir),
            _label: PhantomData,
        }
    }

    pub fn get_name(&self) -> &String {
        &self.name
    }

    pub fn get_labeled_name(&self) -> Labeled<String, L> {
        
        Labeled::new(self.name.clone())
    }

    pub fn hash_code(&self) -> i32 {
        -382_389
    }
}

unsafe impl<L: Label> InvisibleSideEffectFree for PrincipalWrapper<L> {}

pub struct KeyPrincipal<L: Label> {
    pub base: PrincipalWrapper<L>,
    
    pub public_key_pem: String, 
    
    pub keystore_password: Labeled<String, L>, 
    
    pub trusted_ca_file: String, 
}

impl<L: Label> KeyPrincipal<L> {
    pub fn new(name: impl std::fmt::Display, cert_dir: impl std::fmt::Display, keystore_password: Labeled<String, L>) -> Self {
        let name_str = name.to_string();
        let cert_str = cert_dir.to_string();
        KeyPrincipal {
            base: PrincipalWrapper::new(&name_str, &cert_str),
            public_key_pem: format!("-----BEGIN PUBLIC KEY-----\n[{}_rsa_pub_stub]\n-----END PUBLIC KEY-----", name_str),
            keystore_password,
            trusted_ca_file: format!("{}cacert.pem", cert_str),
        }
    }

    pub fn get_private_key(&self) -> Labeled<String, L> {
        println!("[KeyPrincipal] Unlocking keystore for '{}' (requires L clearance)", self.base.name);
        
        Labeled::new(format!("[{}_private_key_stub]", self.base.name))
    }
}

pub struct PolicyStore {
    
    principals: HashMap<String, String>,
    
    delegations: Vec<Delegation>,
    
    pub policy_file: String, 
}

impl PolicyStore {
    
    pub fn new(policy_file: &str) -> Self {
        PolicyStore {
            principals: HashMap::new(),
            delegations: Vec::new(),
            policy_file: policy_file.to_string(),
        }
    }

    pub fn add_principal<L: Label>(&mut self, pw: &PrincipalWrapper<L>) {
        if self.principals.contains_key(&pw.name) {
            println!("[PolicyStore] Warning: principal '{}' already exists", pw.name);
            return;
        }
        self.principals.insert(pw.name.clone(), pw.keystore_path.clone());
        println!("[PolicyStore] Registered principal '{}' (keystore: {})", pw.name, pw.keystore_path);
    }

    pub fn has_principal(&self, name: &str) -> bool {
        self.principals.contains_key(name)
    }

    pub fn get_keystore_path(&self, name: &str) -> Option<&String> {
        self.principals.get(name)
    }

    pub fn list_principals(&self) -> Vec<&String> {
        let mut names: Vec<&String> = self.principals.keys().collect();
        names.sort();
        names
    }

    pub fn add_delegation(&mut self, del: Delegation) {
        println!("[PolicyStore] Delegation: {} → {} (bound: {})", del.delegator, del.delegate, del.label_bound);
        self.delegations.push(del);
    }
}

#[derive(Clone)]
pub struct Delegation {
    
    pub delegator: String, 
    
    pub delegate: String, 
    
    pub label_bound: String, 
}

impl Delegation {
    pub fn new(delegator: &str, delegate: &str, label_bound: &str) -> Self {
        Delegation {
            delegator: delegator.to_string(),
            delegate: delegate.to_string(),
            label_bound: label_bound.to_string(),
        }
    }
}
