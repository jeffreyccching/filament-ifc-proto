// ============================================================================
// Mirrors: jpmail/src/smtp/DigestMD5.jif
//
// Jif source (abridged):
//   class DigestMD5[label L] {
//       // Methods:
//       String{L} authClient(String{} challenge, char{L}[] password,
//                            String{} user, String{} authzid,
//                            String{} realm, String{} digestUri)
//       String{L} authServer(String{} challenge, char{L}[] password, ...)
//       String{L} getAPOPDigest(char{L}[] password, String{} challenge)
//       String{} tokenize(String{} str)
//
//       // Authentication protocol: RFC 2831 DIGEST-MD5
//       // Uses BouncyCastle provider for MD5 and BASE64
//       // Password is char{L}[] — labeled at the principal's security level
//   }
//
// The key IFC property: the DIGEST-MD5 response is labeled L (same as the
// password) because it is derived from the secret password. It cannot be
// printed publicly without an explicit declassification closure.
// ============================================================================

use crate::crypto::{authorized_declassify, DeclassAuthorization};
use macros::mcall;
use typing_rules::lattice::*;

// ============================================================================
// DIGEST-MD5 (SMTP SASL authentication)
// Mirrors: DigestMD5.jif
// ============================================================================

/// DIGEST-MD5 authentication handler for SMTP SASL.
/// Mirrors: DigestMD5[label L] in DigestMD5.jif
///
/// The password is `Labeled<String, L>` — derived values (the challenge
/// response, APOP digest) are also labeled L because they are computed
/// from the secret password.
///
/// In JPmail: authentication is done over the SMTP connection using
/// "AUTH DIGEST-MD5" as specified by RFC 2831.
pub struct DigestMD5<L: Label> {
    /// The user's plaintext password (char{L}[] in Jif — secret credential).
    pub password: Labeled<String, L>,              // char{L}[] password
    /// The authenticating username (String{} in Jif — public, sent in SASL exchange).
    pub username: String,          // String{} user
    /// The realm (String{} in Jif — public, server-provided).
    pub realm: String,             // String{} realm
}

impl<L: Label> DigestMD5<L> {
    pub fn new(password: Labeled<String, L>, username: impl std::fmt::Display, realm: &str) -> Self {
        DigestMD5 {
            password,
            username: username.to_string(),
            realm: realm.to_string(),
        }
    }

    /// Compute the DIGEST-MD5 client response.
    /// Mirrors: authClient(String challenge, char{L}[] password, ...) in DigestMD5.jif
    ///
    /// In JPmail (RFC 2831 sequence):
    ///   Server → Client: Base64(challenge)  [public]
    ///   Client → Server: Base64(response)   [LABELED L — derived from secret]
    ///
    /// Returns `Labeled<String, L>` — the response is secret because it
    /// proves knowledge of the password. Sending it over a Public channel
    /// would require `L: FlowsTo<Public>` — a compile error for Label A.
    ///
    /// In JPmail: the response is declassified via DeclassStringClosure before
    /// being written to the SMTP socket. This is the only legitimate path.
    pub fn auth_client(&self, challenge: Labeled<String, L>) -> Labeled<String, L> {
        println!(
            "[DigestMD5] Computing SASL response for '{}' in realm '{}'",
            self.username, self.realm
        );
        // Stub: real impl follows RFC 2831:
        //   1. Parse challenge for nonce, realm, qop, algorithm
        //   2. Generate client nonce (cnonce)
        //   3. Compute A1 = MD5(MD5(user:realm:password) : nonce : cnonce)
        //   4. Compute A2 = MD5("AUTHENTICATE" : digestUri)
        //   5. Compute response = MD5(A1 : nonce : nc : cnonce : qop : A2)
        let auth = DeclassAuthorization::new(&self.username);
        let response = format!(
            "username=\"{}\",realm=\"{}\",nonce=\"{}\",response=[md5_stub]",
            self.username,
            self.realm,
            authorized_declassify(challenge, &auth)
        );
        Labeled::new(response)
    }

    /// Compute the server-side DIGEST-MD5 verification.
    /// Mirrors: authServer(...) in DigestMD5.jif
    ///
    /// Used when acting as the SMTP server to verify a client's response.
    /// Also labeled L — the server's verification digest is derived from
    /// the same password hash.
    pub fn auth_server(&self, mut client_response: Labeled<String, L>) -> Labeled<bool, L> {
        // Stub: real impl recomputes MD5 and compares
        mcall!(client_response.contains("response="))
    }
}

// ============================================================================
// APOP DIGEST
// Mirrors: getAPOPDigest() in DigestMD5.jif
// Used by MailReaderCrypto for POP3 APOP authentication.
// ============================================================================

/// APOP authentication handler.
///
/// APOP (Authenticated POP) uses MD5(password + server_timestamp).
/// The digest is labeled L because it is derived from the password.
pub struct DigestApop<L: Label> {
    pub password: Labeled<String, L>,
}

impl<L: Label> DigestApop<L> {
    pub fn new(password: Labeled<String, L>) -> Self {
        DigestApop { password }
    }

    /// Compute the APOP digest: MD5(challenge + password).
    /// Mirrors: getAPOPDigest(char{L}[] password, String challenge) in DigestMD5.jif
    ///
    /// In JPmail: uses BouncyCastle MD5 to hash (challenge + password).
    /// Result is a hex string, still labeled L.
    ///
    /// The labeled challenge input is joined with the password label via fcall!.
    pub fn compute_apop_digest(&self, challenge: Labeled<String, L>, auth: &DeclassAuthorization) -> Labeled<String, L> {
        println!("[APOP] Computing MD5 digest (password ⊕ challenge)...");
        // Stub: real impl: MD5(challenge.value + password.value)
        // Both inputs carry label L, so the join is L. Construct directly.
        let _ = &self.password; // consumed in real impl
        Labeled::new(format!("[md5_apop:{}_stub]", authorized_declassify(challenge, auth)))
    }
}
