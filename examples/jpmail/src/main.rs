// ============================================================================
// JPmail: Secure Email with Information Flow Control
// ============================================================================
//
// A Rust port of the JPmail system (ACSAC 2006):
//   "Information Flow Control for Electronic Mail"
//   — Zhiwei Li, Ninghui Li, John C. Mitchell
//   https://www.acsac.org/2006/papers/101.pdf
//
// Original Jif implementation: https://github.com/jeffreyccching/jpmail
//
// This project mirrors the multi-module structure of the original JPmail:
//
//   jifpol/src/policy/  → src/policy.rs       PolicyStore, PrincipalWrapper, KeyPrincipal
//   jifpol/src/util/    → src/password.rs     Password, NewPassword
//   jifpol/src/crypto/  → src/crypto.rs       RSAClosure, DeclassifyHelper
//   jpmail/src/jif/net/ → src/net.rs          SecureSocket (JifSocketFactory)
//   jpmail/src/pop3/    → src/pop3/           MailReaderCrypto + MIME types
//   jpmail/src/smtp/    → src/smtp/           MailSenderCrypto + auth + closures
//
// ============================================================================
// SECURITY LATTICE (from basic_policy.txt)
// ============================================================================
//
//         AB            ← siis group (alice ∪ bob)
//        /  \
//       A    B          ← alice, bob (individual principals)
//        \  /
//        Pub            ← public / bono (nsrc group — untrusted)
//
// Information flow rules (from the lattice):
//   Public → A, B, AB     (public data can enter any confidential context)
//   A      → AB            (alice's data accessible within siis group)
//   B      → AB            (bob's data accessible within siis group)
//   A      ↛ Public        (alice's secrets cannot be downgraded without authority)
//   B      ↛ Public        (bob's secrets cannot be downgraded without authority)
//   A      ↛ B             (alice and bob keep separate secrets)
//
// ============================================================================

mod crypto;
mod net;
mod password;
mod policy;
mod pop3;
mod smtp;

use macros::{fcall, mcall, pc_block};
use policy::{Delegation, PolicyStore, PrincipalWrapper};
use pop3::message::JPMailMessage;
use smtp::MailSenderCrypto;
use typing_rules::lattice::*;

fn main() {
    print_banner();

    // ========================================================================
    // PHASE 0: SETUP — Load policy and bootstrap principals
    // Mirrors: running `ant jifpol` to compile basic_policy.txt, then
    //          `make util/NewPassword ARGS='...'` to set up credentials.
    // ========================================================================

    phase_setup();

    // ========================================================================
    // PHASE 1: jpsendmail — Alice sends a confidential email
    // Mirrors: make smtp/MailSenderCrypto ARGS='alice mail.cse.psu.edu alice alice@cse.psu.edu'
    // ========================================================================

    let alice_mailbox = phase_sendmail();

    // ========================================================================
    // PHASE 2: jpgetmail — Alice reads her own mail (AUTHORIZED)
    // Mirrors: make pop3/MailReaderCrypto ARGS='alice jpmail.cse.psu.edu alice'
    // ========================================================================

    phase_alice_getmail(&alice_mailbox);

    // ========================================================================
    // PHASE 3: jpgetmail — Bono attempts to read Alice's mail (DENIED)
    // Mirrors the JPmail demo: "see how Jif prevents bono from reading alice's mail"
    // ========================================================================

    phase_bono_getmail_denied(&alice_mailbox);

    // ========================================================================
    // PHASE 4: SIIS group mail — Label AB messages (alice + bob authorized)
    // ========================================================================

    phase_siis_group_mail();

    // ========================================================================
    // PHASE 5: Implicit flow control (pc_block!)
    // ========================================================================

    phase_implicit_flow();

    // ========================================================================
    // PHASE 6: Label propagation with fcall! and mcall!
    // ========================================================================

    phase_label_propagation(&alice_mailbox);

    print_footer();
}

// ============================================================================
// PHASE 0 — Setup
// ============================================================================

fn phase_setup() {
    println!("\n╔══ PHASE 0: Setup (policy.properties → basic_policy.txt) ══╗");

    // Build the policy store (mirrors Parser.java reading basic_policy.txt).
    let mut store = PolicyStore::new("basic_policy.txt");

    // Register principals — matches the JPmail demo's basic_policy.txt entries.
    let alice_pw = PrincipalWrapper::<A>::new("alice", "demo/certs-alice/");
    let bob_pw   = PrincipalWrapper::<B>::new("bob",   "demo/certs-bob/");
    let bono_pw  = PrincipalWrapper::<Public>::new("bono", "demo/certs-bono/");

    store.add_principal(&alice_pw);
    store.add_principal(&bob_pw);
    store.add_principal(&bono_pw);

    // Add delegation relationships from basic_policy.txt:
    //   siis → alice   (siis group delegates to alice)
    //   siis → bob     (siis group delegates to bob)
    //   nsrc → bono    (nsrc group delegates to bono)
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
    password::NewPassword::bootstrap(
        "alice",
        Labeled::<String, A>::new("alice_smtp_secret".to_string()),
    );
    password::NewPassword::bootstrap(
        "bob",
        Labeled::<String, B>::new("bob_smtp_secret".to_string()),
    );
    password::NewPassword::bootstrap(
        "bono",
        Labeled::<String, Public>::new("bono_smtp_public".to_string()),
    );
}

// ============================================================================
// PHASE 1 — jpsendmail: Alice sends confidential email
// ============================================================================

fn phase_sendmail() -> Vec<JPMailMessage<A>> {
    println!("\n╔══ PHASE 1: jpsendmail — Alice sends Label-A messages ══╗");
    println!("[jpsendmail] Principal: alice | Server: mail.cse.psu.edu");

    // Alice's SMTP password (labeled A — only alice's context can read it)
    let alice_smtp_pw = Labeled::<String, A>::new("alice_smtp_secret".to_string());
    let sender = MailSenderCrypto::<A>::new(
        "mail.cse.psu.edu",
        "alice",
        "alice@cse.psu.edu",
        alice_smtp_pw,
    );

    // Message 1: Confidential SIIS budget report (Label A)
    let budget_body = Labeled::<String, A>::new(
        "SIIS budget for FY2006: $500,000 total.\n\
         Breakdown: research 60%, hardware 25%, travel 15%.\n\
         DO NOT forward to nsrc group (bono)."
            .to_string(),
    );
    let msg1 = JPMailMessage::<A>::new(
        "alice@cse.psu.edu",
        "alice@cse.psu.edu",
        "SIIS Budget FY2006 (CONFIDENTIAL — Label A)",
        budget_body,
    );
    sender.send_message(&msg1, "alice_rsa_key");

    // Message 2: Internal note from Bob to Alice (Label A — for alice's mailbox)
    let note_body = Labeled::<String, A>::new(
        "Alice, the SIIS project review is Thursday 3pm, room 405.\n\
         Please bring the encryption demo."
            .to_string(),
    );
    let msg2 = JPMailMessage::<A>::new(
        "bob@cse.psu.edu",
        "alice@cse.psu.edu",
        "Meeting Reminder (Label A)",
        note_body,
    );
    sender.send_message(&msg2, "alice_rsa_key");

    // Return the plaintext messages to simulate what alice's POP3 spool holds
    vec![msg1, msg2]
}

// ============================================================================
// PHASE 2 — jpgetmail: Alice reads her own mail
// ============================================================================

fn phase_alice_getmail(messages: &[JPMailMessage<A>]) {
    println!("\n╔══ PHASE 2: jpgetmail — alice reads her Label-A mailbox ══╗");
    println!("[jpgetmail] Principal: alice | Server: jpmail.cse.psu.edu");

    // Alice's MailReaderCrypto<A>: clearance level = A
    let alice_pw = Labeled::<String, A>::new("alice_pop3_secret".to_string());
    let mut reader = pop3::MailReaderCrypto::<A>::new(
        "jpmail.cse.psu.edu",
        "alice",
        Labeled::new("alice".to_string()),
        alice_pw,
    );

    // Simulate the retrieve pipeline (connect → auth → fetch → decrypt)
    reader.retrieve_messages();

    println!(
        "\n[POP3] alice's mailbox: {} messages (Label A — alice authorized)",
        messages.len()
    );

    for (i, msg) in messages.iter().enumerate() {
        println!("\n  ── Message {} ──", i + 1);
        pop3::MailReaderCrypto::<A>::display_headers(msg);
        println!("  Body   : [Labeled<String, A> — confined to alice's context]");
    }

    // mcall! — get message count while preserving label
    let _count: Labeled<usize, A> = reader.message_count();
    println!("\n  [mcall!] Message count: Labeled<usize, A> [label preserved]");
}

// ============================================================================
// PHASE 3 — jpgetmail: Bono attempts to read Alice's mail (DENIED)
// ============================================================================

fn phase_bono_getmail_denied(alice_messages: &[JPMailMessage<A>]) {
    println!("\n╔══ PHASE 3: jpgetmail — bono tries to read alice's Label-A mail ══╗");
    println!("[jpgetmail] Principal: bono | Server: jpmail.cse.psu.edu");
    println!("[IFC] bono has Public clearance. Alice's mailbox is Label A.");

    // Bono's MailReaderCrypto<Public> — clearance = Public
    let bono_pw = Labeled::<String, Public>::new("bono_pop3_pw".to_string());
    let bono_reader = pop3::MailReaderCrypto::<Public>::new(
        "jpmail.cse.psu.edu",
        "bono",
        Labeled::new("bono".to_string()),
        bono_pw,
    );

    println!(
        "\n[POP3] bono connects to alice's spool ({} messages, Label A)...",
        alice_messages.len()
    );

    for (i, msg) in alice_messages.iter().enumerate() {
        println!("\n  ── Message {} (as seen by bono) ──", i + 1);

        // Bono CAN see public metadata (SMTP envelope headers are public)
        pop3::MailReaderCrypto::<A>::display_headers(msg);

        // ─── IFC ENFORCEMENT POINT 1: display_body_publicly ───────────────
        //
        // `display_body_publicly` requires `L: FlowsTo<Public>`.
        // For L = A: `A: FlowsTo<Public>` is NOT implemented.
        // Uncommenting the line below is a COMPILE ERROR:
        //
        //   pop3::MailReaderCrypto::<A>::display_body_publicly(msg);
        //   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
        //   error[E0277]: the trait `FlowsTo<Public>` is not implemented for `A`
        //
        println!("  Body   : [ACCESS DENIED — Label A requires alice's KeyPrincipal<A>]");

        // ─── IFC ENFORCEMENT POINT 2: decrypt with wrong key ──────────────
        //
        // Bono's reader is `MailReaderCrypto<Public>`.
        // His `key_principal: KeyPrincipal<Public>` yields `Labeled<String, Public>`.
        // `MimeMailMessage<A>::decrypt()` requires `Labeled<String, A>` private key.
        // Bono cannot supply a `Labeled<String, A>` — TYPE MISMATCH.
        //
        //   let bono_key: Labeled<String, Public> = bono_reader.key_principal.get_private_key();
        //   some_labeled_mime_a.decrypt(bono_key);  // COMPILE ERROR: expected A, got Public
        //
        println!(
            "  [IFC]  bono's KeyPrincipal<Public> cannot produce Labeled<String, A>."
        );
        println!(
            "  [IFC]  MimeMailMessage<A>::decrypt() requires Labeled<String, A> — denied."
        );
    }

    // Bono CAN read his own Public messages (his reader is MailReaderCrypto<Public>)
    let bono_own_msg = JPMailMessage::<Public>::new(
        "admin@cse.psu.edu",
        "bono@cse.psu.edu",
        "Public announcement",
        Labeled::new("This is a public message. Anyone can read it.".to_string()),
    );
    println!("\n  [Bono reads his own Public mail — authorized]");
    pop3::MailReaderCrypto::<Public>::display_headers(&bono_own_msg);
    // display_body_publicly works for Public: Public: FlowsTo<Public> ✓
    pop3::MailReaderCrypto::<Public>::display_body_publicly(&bono_own_msg);
    println!("  [IFC] Public: FlowsTo<Public> ✓ — bono authorized for his own Label-Public mail.");

    let _ = bono_reader;
}

// ============================================================================
// PHASE 4 — SIIS group email (Label AB = alice ∪ bob)
// ============================================================================

fn phase_siis_group_mail() {
    println!("\n╔══ PHASE 4: SIIS group mail (Label AB = alice ∪ bob) ══╗");

    // Group message labeled AB — both alice (A ≤ AB) and bob (B ≤ AB) can read it
    let group_body = Labeled::<String, AB>::new(
        "SIIS weekly sync: Monday 10am, Zoom link: https://zoom.psu.edu/j/123456\n\
         Agenda: IFC demo, JPmail update, budget review."
            .to_string(),
    );
    let group_msg = JPMailMessage::<AB>::new(
        "admin@cse.psu.edu",
        "siis@cse.psu.edu",
        "SIIS Weekly Sync (Label AB)",
        group_body,
    );

    // Send to SIIS list — both alice's and bob's RSA keys used
    let admin_pw = Labeled::<String, AB>::new("admin_pw_stub".to_string());
    let sender = MailSenderCrypto::<AB>::new(
        "mail.cse.psu.edu",
        "admin",
        "admin@cse.psu.edu",
        admin_pw,
    );
    sender.send_message(&group_msg, "siis_group_rsa_key");

    // Alice reads (A ≤ AB → authorized to access AB content)
    println!("\n  alice reading SIIS group mail (A ≤ AB — authorized):");
    println!("  From   : {}", group_msg.from);
    println!("  Subject: {}", group_msg.subject);
    println!("  Body   : [Labeled<String, AB> — confined to siis group context]");

    // Bob reads (B ≤ AB → authorized)
    println!("\n  bob reading SIIS group mail (B ≤ AB — authorized):");
    println!("  Body   : [Labeled<String, AB> — confined to siis group context]");

    // Bono CANNOT call display_body_publicly on Label AB content:
    //   pop3::MailReaderCrypto::<AB>::display_body_publicly(&group_msg); // COMPILE ERROR
    //   AB: FlowsTo<Public> is NOT implemented
    println!("\n  bono attempting SIIS group mail:");
    println!("  [IFC] AB: FlowsTo<Public> not implemented — bono denied.");
}

// ============================================================================
// PHASE 5 — Implicit Flow Control (pc_block!)
// ============================================================================
//
// Even if bono cannot directly read alice's mail, could he learn its
// contents through a *timing side channel* — e.g., a public counter that
// is updated only when alice has unread mail?
//
// pc_block! prevents this by tracking the Program Counter (PC) label.
// Inside an `if (Label-A condition)`, any assignment must target Label ≥ A.

fn phase_implicit_flow() {
    println!("\n╔══ PHASE 5: Implicit Flow Control (pc_block!) ══╗");
    println!("  Goal: prevent bono from learning alice's secrets via side channels.\n");

    // Alice's secret: whether she has unread confidential mail (Label A)
    let alice_has_unread: Labeled<bool, A> = Labeled::new(true);

    // Public counter — bono can observe this value
    let public_alert_count: Labeled<i32, Public> = Labeled::new(0);

    // Secret audit log (Label A — only alice's context can read it)
    let mut alice_audit: Labeled<i32, A> = Labeled::new(0);
    #[allow(unused_assignments)]
    let _ = &alice_audit;

    // ── SECURE BLOCK ────────────────────────────────────────────────────────
    // pc_block!(A): initial PC = Label A
    //
    // Inside `if alice_has_unread { ... }`:
    //   - Condition is Labeled<bool, A> → PC is raised to A
    //   - Assignments MUST target Label ≥ A
    //
    // VALID:   alice_audit = Labeled::<i32, A>::new(1)   [PC=A → dest=A  ✓]
    // INVALID: public_alert_count = Labeled::<i32, Public>::new(1)
    //          ERROR: PC=A does not FlowsTo<Public> — implicit leak!
    // ────────────────────────────────────────────────────────────────────────
    pc_block! { (A) {
        if alice_has_unread {
            // SAFE: Alice's secret updates alice's audit log (A → A ✓)
            alice_audit = Labeled::<i32, A>::new(1);

            // IMPLICIT LEAK (uncomment to see compile error):
            //   public_alert_count = Labeled::<i32, Public>::new(1);
            //   error[E0277]: FlowsTo<Public> is not implemented for PcContext<A>
        }
    }};

    println!("  alice_audit: Labeled<i32, A>  [only alice can observe — not declassified]");
    println!(
        "  public_alert_count (Public) = {}  [bono sees this — NOT updated inside if(A)]",
        declassify(public_alert_count)
    );
    println!("  [pc_block!] Implicit flow from if(alice_has_unread) blocked successfully.");

    let _ = public_alert_count;
}

// ============================================================================
// PHASE 6 — Label propagation with fcall! and mcall!
// ============================================================================

fn phase_label_propagation(messages: &[JPMailMessage<A>]) {
    println!("\n╔══ PHASE 6: Label propagation (fcall! and mcall!) ══╗");

    if let Some(msg) = messages.first() {
        // ── mcall! ────────────────────────────────────────────────────────
        // mcall! calls a method on a Labeled receiver, preserving its label.
        // `subject` is now a plain String — wrap it in Labeled<String, A>
        // to show mcall! semantics on a labeled value.
        let mut labeled_subject: Labeled<String, A> = Labeled::new(msg.subject.clone());
        let _subject_len: Labeled<usize, A> = mcall!(labeled_subject.len());
        // subject_len is Labeled<usize, A> — the length is still secret!
        println!("  [mcall!] Subject length: Labeled<usize, A>  [label preserved — not declassified]");

        // ── fcall! ────────────────────────────────────────────────────────
        // fcall! wraps a function call: unwraps Labeled args, calls the
        // function, wraps the result with the join of input labels.
        let _body_len: Labeled<usize, A> = fcall!(String::len(msg.body.as_ref()));
        // body_len carries Label A — body.len() is as secret as the body
        println!("  [fcall!] Body length: Labeled<usize, A>  [label joined by fcall! — not declassified]");

        // ── label join ────────────────────────────────────────────────────
        // fcall! on arguments from different principals → label = join(A, B) = AB
        // `msg` is `&JPMailMessage<A>`, so `&mut msg.body` doesn't compile and
        // the `mcall!` macro's `(&mut #base).__mcall_mut(...)` expansion fails.
        // Bypass the macro and call the `&self` form `__mcall` directly for this
        // shared-borrow case.
        let a_size: Labeled<u32, A> = (&msg.body).__mcall(|inner| inner.len()).__map(|v| v as u32);
        let b_size = Labeled::<u32, B>::new(42_u32);
        let _combined: Labeled<u32, AB> = fcall!(u32::saturating_add(a_size, b_size));
        // combined is Labeled<u32, AB> = join(Label A, Label B)
        println!("  [fcall!] alice-bytes + bob-bytes: Labeled<u32, AB> = join(A,B)  [not declassified]");
        println!("  [IFC] Result labeled AB — only siis group can access combined computation.");
    }
}

// ============================================================================
// HELPERS
// ============================================================================

fn print_banner() {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║  JPmail: Secure Email with Information Flow Control            ║");
    println!("║  Rust port · fg_ifc_library (Labeled<T,L>, fcall!, pc_block!) ║");
    println!("║  ACSAC 2006 · github.com/jeffreyccching/jpmail                 ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!("\nSecurity lattice (basic_policy.txt):");
    println!("  AB  ← siis group (alice ∪ bob)");
    println!("  /\\");
    println!(" A  B  ← alice, bob (individual principals)");
    println!("  \\/");
    println!("  Pub ← public / bono (nsrc group)");
    println!("\nPrincipals:");
    println!("  alice (Label A)   — siis, has KeyPrincipal<A>");
    println!("  bob   (Label B)   — siis, has KeyPrincipal<B>");
    println!("  bono  (Public)    — nsrc,  has KeyPrincipal<Public>");
}

fn print_footer() {
    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║  JPmail Demo Complete                                          ║");
    println!("║  IFC enforced:                                                 ║");
    println!("║    • bono cannot decrypt or read Label A / AB mail bodies.     ║");
    println!("║    • pc_block! blocks implicit leaks through conditionals.      ║");
    println!("║    • Declassification only via authorized closures.             ║");
    println!("║    • fcall! / mcall! propagate labels through all operations.   ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
}
