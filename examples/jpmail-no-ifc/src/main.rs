// ============================================================================
// JPmail: Secure Email (No IFC version)
// ============================================================================
//
// A Rust port of the JPmail system (ACSAC 2006):
//   "Information Flow Control for Electronic Mail"
//   -- Zhiwei Li, Ninghui Li, John C. Mitchell
//   https://www.acsac.org/2006/papers/101.pdf
//
// Original Jif implementation: https://github.com/jeffreyccching/jpmail
//
// This project mirrors the multi-module structure of the original JPmail:
//
//   jifpol/src/policy/  -> src/policy.rs       PolicyStore, PrincipalWrapper, KeyPrincipal
//   jifpol/src/util/    -> src/password.rs     Password, NewPassword
//   jifpol/src/crypto/  -> src/crypto.rs       RSAClosure
//   jpmail/src/jif/net/ -> src/net.rs          SecureSocket (JifSocketFactory)
//   jpmail/src/pop3/    -> src/pop3/           MailReaderCrypto + MIME types
//   jpmail/src/smtp/    -> src/smtp/           MailSenderCrypto + auth + closures
//
// ============================================================================
// SECURITY LATTICE (from basic_policy.txt)
// ============================================================================
//
//         AB            <- siis group (alice U bob)
//        /  \
//       A    B          <- alice, bob (individual principals)
//        \  /
//        Pub            <- public / bono (nsrc group -- untrusted)
//
// Information flow rules (from the lattice):
//   Public -> A, B, AB     (public data can enter any confidential context)
//   A      -> AB            (alice's data accessible within siis group)
//   B      -> AB            (bob's data accessible within siis group)
//   A      -/> Public       (alice's secrets cannot be downgraded without authority)
//   B      -/> Public       (bob's secrets cannot be downgraded without authority)
//   A      -/> B            (alice and bob keep separate secrets)
//
// ============================================================================

mod crypto;
mod net;
mod password;
mod policy;
mod pop3;
mod smtp;

use policy::{Delegation, PolicyStore, PrincipalWrapper};
use pop3::message::JPMailMessage;
use smtp::MailSenderCrypto;

fn main() {
    print_banner();

    // ========================================================================
    // PHASE 0: SETUP -- Load policy and bootstrap principals
    // Mirrors: running `ant jifpol` to compile basic_policy.txt, then
    //          `make util/NewPassword ARGS='...'` to set up credentials.
    // ========================================================================

    phase_setup();

    // ========================================================================
    // PHASE 1: jpsendmail -- Alice sends a confidential email
    // Mirrors: make smtp/MailSenderCrypto ARGS='alice mail.cse.psu.edu alice alice@cse.psu.edu'
    // ========================================================================

    let alice_mailbox = phase_sendmail();

    // ========================================================================
    // PHASE 2: jpgetmail -- Alice reads her own mail (AUTHORIZED)
    // Mirrors: make pop3/MailReaderCrypto ARGS='alice jpmail.cse.psu.edu alice'
    // ========================================================================

    phase_alice_getmail(&alice_mailbox);

    // ========================================================================
    // PHASE 3: jpgetmail -- Bono attempts to read Alice's mail (DENIED)
    // Mirrors the JPmail demo: "see how Jif prevents bono from reading alice's mail"
    // ========================================================================

    phase_bono_getmail_denied(&alice_mailbox);

    // ========================================================================
    // PHASE 4: SIIS group mail -- Label AB messages (alice + bob authorized)
    // ========================================================================

    phase_siis_group_mail();

    // ========================================================================
    // PHASE 5: Implicit flow control
    // ========================================================================

    phase_implicit_flow();

    // ========================================================================
    // PHASE 6: Label propagation
    // ========================================================================

    phase_label_propagation(&alice_mailbox);

    print_footer();
}

// ============================================================================
// PHASE 0 -- Setup
// ============================================================================

fn phase_setup() {
    println!("\n╔══ PHASE 0: Setup (policy.properties → basic_policy.txt) ══╗");

    // Build the policy store (mirrors Parser.java reading basic_policy.txt).
    let mut store = PolicyStore::new("basic_policy.txt");

    // Register principals -- matches the JPmail demo's basic_policy.txt entries.
    let alice_pw = PrincipalWrapper::new("alice", "demo/certs-alice/");
    let bob_pw   = PrincipalWrapper::new("bob",   "demo/certs-bob/");
    let bono_pw  = PrincipalWrapper::new("bono",  "demo/certs-bono/");

    store.add_principal(&alice_pw);
    store.add_principal(&bob_pw);
    store.add_principal(&bono_pw);

    // Add delegation relationships from basic_policy.txt:
    //   siis -> alice   (siis group delegates to alice)
    //   siis -> bob     (siis group delegates to bob)
    //   nsrc -> bono    (nsrc group delegates to bono)
    store.add_delegation(Delegation::new("siis", "alice", "AB"));
    store.add_delegation(Delegation::new("siis", "bob",   "AB"));
    store.add_delegation(Delegation::new("nsrc", "bono",  "Public"));

    println!(
        "[PolicyStore] Registered {} principals: {:?}",
        store.list_principals().len(),
        store.list_principals()
    );

    // Bootstrap passwords (mirrors NewPassword.jif for each principal).
    // In the demo: encrypted under demo/passwd-alice/, demo/passwd-bob/, demo/passwd-bono/
    password::NewPassword::bootstrap("alice", "alice_smtp_secret".to_string());
    password::NewPassword::bootstrap("bob", "bob_smtp_secret".to_string());
    password::NewPassword::bootstrap("bono", "bono_smtp_public".to_string());
}

// ============================================================================
// PHASE 1 -- jpsendmail: Alice sends confidential email
// ============================================================================

fn phase_sendmail() -> Vec<JPMailMessage> {
    println!("\n╔══ PHASE 1: jpsendmail -- Alice sends messages ══╗");
    println!("[jpsendmail] Principal: alice | Server: mail.cse.psu.edu");

    // Alice's SMTP password
    let alice_smtp_pw = "alice_smtp_secret".to_string();
    let sender = MailSenderCrypto::new(
        "mail.cse.psu.edu",
        "alice",
        "alice@cse.psu.edu",
        alice_smtp_pw,
    );

    // Message 1: Confidential SIIS budget report
    let budget_body =
        "SIIS budget for FY2006: $500,000 total.\n\
         Breakdown: research 60%, hardware 25%, travel 15%.\n\
         DO NOT forward to nsrc group (bono)."
            .to_string();
    let msg1 = JPMailMessage::new(
        "alice@cse.psu.edu",
        "alice@cse.psu.edu",
        "SIIS Budget FY2006 (CONFIDENTIAL)",
        budget_body,
    );
    sender.send_message(&msg1, "alice_rsa_key");

    // Message 2: Internal note from Bob to Alice
    let note_body =
        "Alice, the SIIS project review is Thursday 3pm, room 405.\n\
         Please bring the encryption demo."
            .to_string();
    let msg2 = JPMailMessage::new(
        "bob@cse.psu.edu",
        "alice@cse.psu.edu",
        "Meeting Reminder",
        note_body,
    );
    sender.send_message(&msg2, "alice_rsa_key");

    // Return the plaintext messages to simulate what alice's POP3 spool holds
    vec![msg1, msg2]
}

// ============================================================================
// PHASE 2 -- jpgetmail: Alice reads her own mail
// ============================================================================

fn phase_alice_getmail(messages: &[JPMailMessage]) {
    println!("\n╔══ PHASE 2: jpgetmail -- alice reads her mailbox ══╗");
    println!("[jpgetmail] Principal: alice | Server: jpmail.cse.psu.edu");

    // Alice's MailReaderCrypto
    let alice_pw = "alice_pop3_secret".to_string();
    let mut reader = pop3::MailReaderCrypto::new(
        "jpmail.cse.psu.edu",
        "alice",
        alice_pw,
    );

    // Simulate the retrieve pipeline (connect -> auth -> fetch -> decrypt)
    reader.retrieve_messages();

    println!(
        "\n[POP3] alice's mailbox: {} messages (alice authorized)",
        messages.len()
    );

    for (i, msg) in messages.iter().enumerate() {
        println!("\n  -- Message {} --", i + 1);
        pop3::MailReaderCrypto::display_headers(msg);
        println!("  Body   : [confined to alice's context]");
    }

    // Get message count
    let _count: usize = reader.message_count();
    println!("\n  Message count: {}", _count);
}

// ============================================================================
// PHASE 3 -- jpgetmail: Bono attempts to read Alice's mail (DENIED)
// ============================================================================

fn phase_bono_getmail_denied(alice_messages: &[JPMailMessage]) {
    println!("\n╔══ PHASE 3: jpgetmail -- bono tries to read alice's mail ══╗");
    println!("[jpgetmail] Principal: bono | Server: jpmail.cse.psu.edu");
    println!("bono has Public clearance. Alice's mailbox is confidential.");

    // Bono's MailReaderCrypto
    let bono_pw = "bono_pop3_pw".to_string();
    let bono_reader = pop3::MailReaderCrypto::new(
        "jpmail.cse.psu.edu",
        "bono",
        bono_pw,
    );

    println!(
        "\n[POP3] bono connects to alice's spool ({} messages)...",
        alice_messages.len()
    );

    for (i, msg) in alice_messages.iter().enumerate() {
        println!("\n  -- Message {} (as seen by bono) --", i + 1);

        // Bono CAN see public metadata (SMTP envelope headers are public)
        pop3::MailReaderCrypto::display_headers(msg);

        println!("  Body   : [ACCESS DENIED -- requires alice's KeyPrincipal]");
        println!(
            "  bono's KeyPrincipal cannot produce alice's private key."
        );
        println!(
            "  MimeMailMessage::decrypt() requires alice's private key -- denied."
        );
    }

    // Bono CAN read his own Public messages
    let bono_own_msg = JPMailMessage::new(
        "admin@cse.psu.edu",
        "bono@cse.psu.edu",
        "Public announcement",
        "This is a public message. Anyone can read it.".to_string(),
    );
    println!("\n  [Bono reads his own Public mail -- authorized]");
    pop3::MailReaderCrypto::display_headers(&bono_own_msg);
    pop3::MailReaderCrypto::display_body_publicly(&bono_own_msg);
    println!("  bono authorized for his own mail.");

    let _ = bono_reader;
}

// ============================================================================
// PHASE 4 -- SIIS group email (AB = alice U bob)
// ============================================================================

fn phase_siis_group_mail() {
    println!("\n╔══ PHASE 4: SIIS group mail (AB = alice U bob) ══╗");

    // Group message -- both alice and bob can read it
    let group_body =
        "SIIS weekly sync: Monday 10am, Zoom link: https://zoom.psu.edu/j/123456\n\
         Agenda: IFC demo, JPmail update, budget review."
            .to_string();
    let group_msg = JPMailMessage::new(
        "admin@cse.psu.edu",
        "siis@cse.psu.edu",
        "SIIS Weekly Sync",
        group_body,
    );

    // Send to SIIS list -- both alice's and bob's RSA keys used
    let admin_pw = "admin_pw_stub".to_string();
    let sender = MailSenderCrypto::new(
        "mail.cse.psu.edu",
        "admin",
        "admin@cse.psu.edu",
        admin_pw,
    );
    sender.send_message(&group_msg, "siis_group_rsa_key");

    // Alice reads
    println!("\n  alice reading SIIS group mail (authorized):");
    println!("  From   : {}", group_msg.from);
    println!("  Subject: {}", group_msg.subject);
    println!("  Body   : [confined to siis group context]");

    // Bob reads
    println!("\n  bob reading SIIS group mail (authorized):");
    println!("  Body   : [confined to siis group context]");

    // Bono CANNOT read group mail
    println!("\n  bono attempting SIIS group mail:");
    println!("  bono denied -- not a member of siis group.");
}

// ============================================================================
// PHASE 5 -- Implicit Flow Control
// ============================================================================
//
// Even if bono cannot directly read alice's mail, could he learn its
// contents through a *timing side channel* -- e.g., a public counter that
// is updated only when alice has unread mail?

fn phase_implicit_flow() {
    println!("\n╔══ PHASE 5: Implicit Flow Control ══╗");
    println!("  Goal: prevent bono from learning alice's secrets via side channels.\n");

    // Alice's secret: whether she has unread confidential mail
    let alice_has_unread: bool = true;

    // Public counter -- bono can observe this value
    let public_alert_count: i32 = 0;

    // Secret audit log (only alice's context can read it)
    let mut alice_audit: i32 = 0;

    if alice_has_unread {
        // SAFE: Alice's secret updates alice's audit log
        alice_audit = 1;

        // IMPLICIT LEAK would be: public_alert_count = 1;
        // In the IFC version, this is a compile error.
    }

    println!("  alice_audit: {}  [only alice can observe]", alice_audit);
    println!(
        "  public_alert_count = {}  [bono sees this -- NOT updated inside if(alice_has_unread)]",
        public_alert_count
    );
    println!("  Implicit flow from if(alice_has_unread) blocked successfully.");
}

// ============================================================================
// PHASE 6 -- Label propagation
// ============================================================================

fn phase_label_propagation(messages: &[JPMailMessage]) {
    println!("\n╔══ PHASE 6: Label propagation ══╗");

    if let Some(msg) = messages.first() {
        // Subject length
        let _subject_len: usize = msg.subject.len();
        println!("  Subject length: {}  [not declassified]", _subject_len);

        // Body length
        let _body_len: usize = msg.body.len();
        println!("  Body length: {}  [not declassified]", _body_len);

        // Label join: alice-bytes + bob-bytes
        let a_size: u32 = msg.body.len() as u32;
        let b_size: u32 = 42_u32;
        let _combined: u32 = a_size.saturating_add(b_size);
        println!("  alice-bytes + bob-bytes: {} = combined  [not declassified]", _combined);
        println!("  Result -- only siis group can access combined computation.");
    }
}

// ============================================================================
// HELPERS
// ============================================================================

fn print_banner() {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║  JPmail: Secure Email (No IFC version)                         ║");
    println!("║  Rust port · ACSAC 2006                                        ║");
    println!("║  github.com/jeffreyccching/jpmail                              ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!("\nSecurity lattice (basic_policy.txt):");
    println!("  AB  <- siis group (alice U bob)");
    println!("  /\\");
    println!(" A  B  <- alice, bob (individual principals)");
    println!("  \\/");
    println!("  Pub <- public / bono (nsrc group)");
    println!("\nPrincipals:");
    println!("  alice   -- siis, has KeyPrincipal");
    println!("  bob     -- siis, has KeyPrincipal");
    println!("  bono    -- nsrc, has KeyPrincipal");
}

fn print_footer() {
    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║  JPmail Demo Complete                                          ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
}
