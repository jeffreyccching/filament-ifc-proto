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
use std::marker::PhantomData;
use typing_rules::implicit::InvisibleSideEffectFree;
use typing_rules::lattice::*;

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
/// The type parameter L is the security label for this principal:
///   - alice -> PrincipalWrapper<A>   (only alice's context can access her data)
///   - bob   -> PrincipalWrapper<B>
///   - bono  -> PrincipalWrapper<Public>
///
/// In JPmail: PrincipalWrapper.hashCode() always returns -382389 (hardcoded in
/// the Jif source) — we keep the same quirky constant here for fidelity.
#[derive(Clone)]
pub struct PrincipalWrapper<L: Label> {
    /// Principal's human-readable name (String{} in Jif — always public).
    pub name: String, // String{} name
    /// Path to this principal's keystore directory (String{} — public info).
    pub keystore_path: String, // String{} — public
    /// Path to the trusted CA certificate (String{} — public info).
    pub cert_path: String, // String{} — public
    _label: PhantomData<L>,
}

impl<L: Label> PrincipalWrapper<L> {
    /// Create a new principal wrapper.
    /// Mirrors: PrincipalWrapper(label l, Principal p, String name) constructor.
    pub fn new(name: impl std::fmt::Display, cert_dir: impl std::fmt::Display) -> Self {
        PrincipalWrapper {
            name: name.to_string(),
            keystore_path: format!("{}{}.keystore", cert_dir, name),
            cert_path: format!("{}cacert.pem", cert_dir),
            _label: PhantomData,
        }
    }

    /// Return the principal name.
    /// Mirrors: getName() -> String in PrincipalWrapper.jif
    pub fn get_name(&self) -> &String {
        &self.name
    }

    /// Return this principal's label-wrapped identity string.
    /// The name itself is public but the Labeled wrapper signals the principal's
    /// security context for use in label-aware code.
    pub fn get_labeled_name(&self) -> Labeled<String, L> {
        // Public → L is always safe (upgrading from bottom label)
        Labeled::new(self.name.clone())
    }

    /// Hardcoded hash — mirrors PrincipalWrapper.hashCode() returning -382389.
    pub fn hash_code(&self) -> i32 {
        -382_389
    }
}

unsafe impl<L: Label> InvisibleSideEffectFree for PrincipalWrapper<L> {}

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
/// The keystore password is `Labeled<String, L>` — only code running at
/// clearance L can read the private key, which is required to decrypt mail.
///
/// In the JPmail demo:
///   Alice uses KeyPrincipal<A> → can decrypt Labeled<_, A> ciphertext
///   Bono  uses KeyPrincipal<Public> → cannot decrypt Labeled<_, A> ciphertext
// #[derive(Debug)]
pub struct KeyPrincipal<L: Label> {
    pub base: PrincipalWrapper<L>,
    /// RSA public key in PEM format (String{} — public, widely distributed for encryption).
    pub public_key_pem: String, // PublicKey — public
    /// Keystore password (String{this:} in Jif — labeled L, the owner must keep this secret).
    pub keystore_password: Labeled<String, L>, // String{this:} keystorePwd
    /// Path to the trusted CA file (String{} — public).
    pub trusted_ca_file: String, // String{} trustedCAfilename
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

    /// Retrieve the RSA private key by unlocking the keystore.
    /// Mirrors: getPrivateKey() in KeyPrincipal.jif
    ///
    /// In JPmail: requires `where caller(this)` — only the owning principal
    /// can invoke this. In Rust: the return type Labeled<String, L> enforces
    /// that the private key stays at clearance L.
    ///
    /// Alice  → returns Labeled<String, A>  (only alice's context can use it)
    /// Bono   → returns Labeled<String, Public> (only unlocks bono's key, not alice's)
    pub fn get_private_key(&self) -> Labeled<String, L> {
        println!("[KeyPrincipal] Unlocking keystore for '{}' (requires L clearance)", self.base.name);
        // Stub: real impl calls runtime.getKeyPair(keystoreFilename, keystorePwd)
        Labeled::new(format!("[{}_private_key_stub]", self.base.name))
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
// Loaded from: policy.properties → basic_policy.txt
//   policy.dir=jifpol/policies
//   policy.file=basic_policy.txt
// ============================================================================

/// Stores all known principals and their public key paths.
///
/// In JPmail, the policy store is populated by the JifPolicyTool compiler
/// which reads basic_policy.txt and generates Jif principal classes.
///
/// Demo principals (from basic_policy.txt):
///   alice → Label A   (siis group member)
///   bob   → Label B   (siis group member)
///   bono  → Public    (nsrc group — cannot access siis secrets)
///   siis  → Label AB  (the group label, join of A and B)
pub struct PolicyStore {
    /// Map: principal name → keystore path (all String{} — public information).
    principals: HashMap<String, String>,
    /// Delegation records (from -> to, label bound — all public).
    delegations: Vec<Delegation>,
    /// Policy file path (String{} — public).
    pub policy_file: String, // String{} — public
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
    /// Enforces uniqueness — duplicate names are rejected (mirroring the
    /// "uniqueness checking" described in the Jif source comments).
    pub fn add_principal<L: Label>(&mut self, pw: &PrincipalWrapper<L>) {
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
    /// Constraint: {p1:} <= lb (enforced by the Jif type system; documented here).
    pub fn add_delegation(&mut self, del: Delegation) {
        println!("[PolicyStore] Delegation: {} → {} (bound: {})", del.delegator, del.delegate, del.label_bound);
        self.delegations.push(del);
    }
}

// ============================================================================
// DELEGATION
// Mirrors: jifpol/src/policy/PolicyUtil.jif
//          jifpol/src/policy/AddDelClosureL.jif
//
// Jif source (AddDelClosureL.jif):
//   class AddDelClosureL[principal P, label L] implements Closure[P, L] {
//       final Principal del;  // the delegate principal
//       invoke() { addDelegatesTo(del); }
//   }
//
// Jif source (PolicyUtil.jif):
//   delegate(principal p1, principal p2, label lb) {
//       // Constraint: {p1:} <= lb
//       AddDelClosureL[p1, lb] c = new AddDelClosureL[p1, lb](p2);
//       PrincipalUtil.authorize(p1, c, lb, lb);
//   }
// ============================================================================

/// Records a delegation relationship between two principals.
///
/// In JPmail's basic_policy.txt:
///   siis -> alice    (siis delegates to alice)
///   siis -> bob      (siis delegates to bob)
///   nsrc -> bono     (nsrc delegates to bono)
#[derive(Clone)]
pub struct Delegation {
    /// The principal granting authority (String{} — public, delegation is visible).
    pub delegator: String, // String{} — public
    /// The principal receiving authority (String{} — public).
    pub delegate: String, // String{} — public
    /// The label bound at which delegation holds (String{} — Public/A/B/AB).
    pub label_bound: String, // String{} — public
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
