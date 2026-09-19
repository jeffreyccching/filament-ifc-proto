// ============================================================================
// Mirrors: jifpol/src/policy/PolicyStore.jif
//          jifpol/src/policy/PrincipalWrapper.jif
//          jifpol/src/policy/KeyPrincipal.jif
//          jifpol/src/policy/MainPrincipal.jif
//          jifpol/src/policy/PolicyUtil.jif
//          jifpol/src/policy/AddDelClosureL.jif
//          jifpol/jifpolicytool/Principal.java
//
// The policy framework loads principal definitions from basic_policy.txt
// (pointed to by policy.properties) and makes them available at runtime.
// Each principal has an associated security label and key material.
// ============================================================================

use std::collections::HashMap;

// ============================================================================
// PRINCIPAL WRAPPER
// Mirrors: jifpol/src/policy/PrincipalWrapper.jif
//
// Jif source:
//   class PrincipalWrapper[label l] {
//       protected final label l;
//       protected final Principal p;
//       protected final String{} name;
//       getPrincipal() -> Principal
//       getName() -> String
//       getLabel() -> label
//   }
// ============================================================================

/// Wraps a principal with its associated security label.
///
/// In JPmail: PrincipalWrapper.hashCode() always returns -382389 (hardcoded in
/// the Jif source) -- we keep the same quirky constant here for fidelity.
#[derive(Clone)]
pub struct PrincipalWrapper {
    /// Principal's human-readable name (always public).
    pub name: String,
    /// Path to this principal's keystore directory (public info).
    pub keystore_path: String,
    /// Path to the trusted CA certificate (public info).
    pub cert_path: String,
}

impl PrincipalWrapper {
    /// Create a new principal wrapper.
    /// Mirrors: PrincipalWrapper(label l, Principal p, String name) constructor.
    pub fn new(name: impl std::fmt::Display, cert_dir: impl std::fmt::Display) -> Self {
        PrincipalWrapper {
            name: name.to_string(),
            keystore_path: format!("{}{}.keystore", cert_dir, name),
            cert_path: format!("{}cacert.pem", cert_dir),
        }
    }

    /// Return the principal name.
    /// Mirrors: getName() -> String in PrincipalWrapper.jif
    pub fn get_name(&self) -> &String {
        &self.name
    }

    /// Hardcoded hash -- mirrors PrincipalWrapper.hashCode() returning -382389.
    pub fn hash_code(&self) -> i32 {
        -382_389
    }
}

// ============================================================================
// KEY PRINCIPAL
// Mirrors: jifpol/src/policy/KeyPrincipal.jif
//
// Jif source (abridged):
//   class KeyPrincipal[L] extends PrincipalWrapper[L] {
//       final PublicKey publicKey;
//       String{this:}  keystorePwd;   // password is labeled at owner's level
//       String         keystoreFilename;
//       String         trustedCAfilename;
//       PrivateKey getPrivateKey() where caller(this) { ... }
//   }
// ============================================================================

/// A principal that holds RSA key material.
///
/// The keystore password is secret -- only the owner can read the private key,
/// which is required to decrypt mail.
///
/// In the JPmail demo:
///   Alice uses KeyPrincipal -> can decrypt alice's ciphertext
///   Bono  uses KeyPrincipal -> cannot decrypt alice's ciphertext
pub struct KeyPrincipal {
    pub base: PrincipalWrapper,
    /// RSA public key in PEM format (public, widely distributed for encryption).
    pub public_key_pem: String,
    /// Keystore password (secret -- the owner must keep this secret).
    pub keystore_password: String,
    /// Path to the trusted CA file (public).
    pub trusted_ca_file: String,
}

impl KeyPrincipal {
    pub fn new(name: impl std::fmt::Display, cert_dir: impl std::fmt::Display, keystore_password: String) -> Self {
        let name_str = name.to_string();
        let cert_str = cert_dir.to_string();
        KeyPrincipal {
            base: PrincipalWrapper::new(&name_str, &cert_str),
            public_key_pem: format!("-----BEGIN PUBLIC KEY-----\n[{}_rsa_pub_stub]\n-----END PUBLIC KEY-----", name_str),
            keystore_password,
            trusted_ca_file: format!("{}cacert.pem", cert_str),
        }
    }

    /// Retrieve the RSA private key by unlocking the keystore.
    /// Mirrors: getPrivateKey() in KeyPrincipal.jif
    ///
    /// In JPmail: requires `where caller(this)` -- only the owning principal
    /// can invoke this.
    pub fn get_private_key(&self) -> String {
        println!("[KeyPrincipal] Unlocking keystore for '{}'", self.base.name);
        // Stub: real impl calls runtime.getKeyPair(keystoreFilename, keystorePwd)
        format!("[{}_private_key_stub]", self.base.name)
    }
}

// ============================================================================
// POLICY STORE
// Mirrors: jifpol/src/policy/PolicyStore.jif
//
// Jif source:
//   class PolicyStore[principal Manager, label L] {
//       getPrincipal(String name)    -> PrincipalWrapper[L]
//       hasPrincipal(String name)    -> boolean
//       getPrincipalLabel(String n)  -> label
//       addPrincipal(PrincipalWrapper[L] pw)
//   }
//
// Loaded from: policy.properties -> basic_policy.txt
//   policy.dir=jifpol/policies
//   policy.file=basic_policy.txt
// ============================================================================

/// Stores all known principals and their public key paths.
///
/// In JPmail, the policy store is populated by the JifPolicyTool compiler
/// which reads basic_policy.txt and generates Jif principal classes.
///
/// Demo principals (from basic_policy.txt):
///   alice  (siis group member)
///   bob    (siis group member)
///   bono   (nsrc group -- cannot access siis secrets)
///   siis   (the group, join of alice and bob)
pub struct PolicyStore {
    /// Map: principal name -> keystore path (all public information).
    principals: HashMap<String, String>,
    /// Delegation records (from -> to, label bound -- all public).
    delegations: Vec<Delegation>,
    /// Policy file path (public).
    pub policy_file: String,
}

impl PolicyStore {
    /// Create a new policy store.
    /// Mirrors: PolicyStore() constructor; policy_file corresponds to
    /// the `policy.file` property in policy.properties.
    pub fn new(policy_file: &str) -> Self {
        PolicyStore {
            principals: HashMap::new(),
            delegations: Vec::new(),
            policy_file: policy_file.to_string(),
        }
    }

    /// Register a principal. Mirrors: addPrincipal() in PolicyStore.jif.
    /// Enforces uniqueness -- duplicate names are rejected (mirroring the
    /// "uniqueness checking" described in the Jif source comments).
    pub fn add_principal(&mut self, pw: &PrincipalWrapper) {
        if self.principals.contains_key(&pw.name) {
            println!("[PolicyStore] Warning: principal '{}' already exists", pw.name);
            return;
        }
        self.principals.insert(pw.name.clone(), pw.keystore_path.clone());
        println!("[PolicyStore] Registered principal '{}' (keystore: {})", pw.name, pw.keystore_path);
    }

    /// Check if a principal is registered. Mirrors: hasPrincipal() in PolicyStore.jif.
    pub fn has_principal(&self, name: &str) -> bool {
        self.principals.contains_key(name)
    }

    /// Get the keystore path for a principal (public information).
    pub fn get_keystore_path(&self, name: &str) -> Option<&String> {
        self.principals.get(name)
    }

    /// List all registered principal names.
    pub fn list_principals(&self) -> Vec<&String> {
        let mut names: Vec<&String> = self.principals.keys().collect();
        names.sort();
        names
    }

    /// Add a delegation relationship.
    /// Mirrors: PolicyUtil.delegate(p1, p2, lb) in PolicyUtil.jif
    pub fn add_delegation(&mut self, del: Delegation) {
        println!("[PolicyStore] Delegation: {} → {} (bound: {})", del.delegator, del.delegate, del.label_bound);
        self.delegations.push(del);
    }
}

// ============================================================================
// DELEGATION
// Mirrors: jifpol/src/policy/PolicyUtil.jif
//          jifpol/src/policy/AddDelClosureL.jif
// ============================================================================

/// Records a delegation relationship between two principals.
///
/// In JPmail's basic_policy.txt:
///   siis -> alice    (siis delegates to alice)
///   siis -> bob      (siis delegates to bob)
///   nsrc -> bono     (nsrc delegates to bono)
#[derive(Clone)]
pub struct Delegation {
    /// The principal granting authority (public, delegation is visible).
    pub delegator: String,
    /// The principal receiving authority (public).
    pub delegate: String,
    /// The label bound at which delegation holds (Public/A/B/AB).
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
