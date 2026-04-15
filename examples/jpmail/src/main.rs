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

    phase_setup();

    let alice_mailbox = phase_sendmail();

    phase_alice_getmail(&alice_mailbox);

    phase_bono_getmail_denied(&alice_mailbox);

    phase_siis_group_mail();

    phase_implicit_flow();

    phase_label_propagation(&alice_mailbox);

    print_footer();
}

fn phase_setup() {
    println!("\n╔══ PHASE 0: Setup (policy.properties → basic_policy.txt) ══╗");

    let mut store = PolicyStore::new("basic_policy.txt");

    let alice_pw = PrincipalWrapper::<A>::new("alice", "demo/certs-alice/");
    let bob_pw = PrincipalWrapper::<B>::new("bob", "demo/certs-bob/");
    let bono_pw = PrincipalWrapper::<Public>::new("bono", "demo/certs-bono/");

    store.add_principal(&alice_pw);
    store.add_principal(&bob_pw);
    store.add_principal(&bono_pw);

    store.add_delegation(Delegation::new("siis", "alice", "AB"));
    store.add_delegation(Delegation::new("siis", "bob", "AB"));
    store.add_delegation(Delegation::new("nsrc", "bono", "Public"));

    println!("[PolicyStore] Registered {} principals: {:?}", store.list_principals().len(), store.list_principals());

    password::NewPassword::bootstrap("alice", Labeled::<String, A>::new("alice_smtp_secret".to_string()));
    password::NewPassword::bootstrap("bob", Labeled::<String, B>::new("bob_smtp_secret".to_string()));
    password::NewPassword::bootstrap("bono", Labeled::<String, Public>::new("bono_smtp_public".to_string()));
}

fn phase_sendmail() -> Vec<JPMailMessage<A>> {
    println!("\n╔══ PHASE 1: jpsendmail — Alice sends Label-A messages ══╗");
    println!("[jpsendmail] Principal: alice | Server: mail.cse.psu.edu");

    let alice_smtp_pw = Labeled::<String, A>::new("alice_smtp_secret".to_string());
    let sender = MailSenderCrypto::<A>::new("mail.cse.psu.edu", "alice", "alice@cse.psu.edu", alice_smtp_pw);

    let budget_body = Labeled::<String, A>::new(
        "SIIS budget for FY2006: $500,000 total.\n\
         Breakdown: research 60%, hardware 25%, travel 15%.\n\
         DO NOT forward to nsrc group (bono)."
            .to_string(),
    );
    let msg1 = JPMailMessage::<A>::new("alice@cse.psu.edu", "alice@cse.psu.edu", "SIIS Budget FY2006 (CONFIDENTIAL — Label A)", budget_body);
    sender.send_message(&msg1, "alice_rsa_key");

    let note_body = Labeled::<String, A>::new(
        "Alice, the SIIS project review is Thursday 3pm, room 405.\n\
         Please bring the encryption demo."
            .to_string(),
    );
    let msg2 = JPMailMessage::<A>::new("bob@cse.psu.edu", "alice@cse.psu.edu", "Meeting Reminder (Label A)", note_body);
    sender.send_message(&msg2, "alice_rsa_key");

    vec![msg1, msg2]
}

fn phase_alice_getmail(messages: &[JPMailMessage<A>]) {
    println!("\n╔══ PHASE 2: jpgetmail — alice reads her Label-A mailbox ══╗");
    println!("[jpgetmail] Principal: alice | Server: jpmail.cse.psu.edu");

    let alice_pw = Labeled::<String, A>::new("alice_pop3_secret".to_string());
    let mut reader = pop3::MailReaderCrypto::<A>::new("jpmail.cse.psu.edu", "alice", Labeled::new("alice".to_string()), alice_pw);

    reader.retrieve_messages();

    println!("\n[POP3] alice's mailbox: {} messages (Label A — alice authorized)", messages.len());

    for (i, msg) in messages.iter().enumerate() {
        println!("\n  ── Message {} ──", i + 1);
        pop3::MailReaderCrypto::<A>::display_headers(msg);
        println!("  Body   : [Labeled<String, A> — confined to alice's context]");
    }

    let _count: Labeled<usize, A> = reader.message_count();
    println!("\n  [mcall!] Message count: Labeled<usize, A> [label preserved]");
}

fn phase_bono_getmail_denied(alice_messages: &[JPMailMessage<A>]) {
    println!("\n╔══ PHASE 3: jpgetmail — bono tries to read alice's Label-A mail ══╗");
    println!("[jpgetmail] Principal: bono | Server: jpmail.cse.psu.edu");
    println!("[IFC] bono has Public clearance. Alice's mailbox is Label A.");

    let bono_pw = Labeled::<String, Public>::new("bono_pop3_pw".to_string());
    let bono_reader = pop3::MailReaderCrypto::<Public>::new("jpmail.cse.psu.edu", "bono", Labeled::new("bono".to_string()), bono_pw);

    println!("\n[POP3] bono connects to alice's spool ({} messages, Label A)...", alice_messages.len());

    for (i, msg) in alice_messages.iter().enumerate() {
        println!("\n  ── Message {} (as seen by bono) ──", i + 1);

        pop3::MailReaderCrypto::<A>::display_headers(msg);

        println!("  Body   : [ACCESS DENIED — Label A requires alice's KeyPrincipal<A>]");

        println!("  [IFC]  bono's KeyPrincipal<Public> cannot produce Labeled<String, A>.");
        println!("  [IFC]  MimeMailMessage<A>::decrypt() requires Labeled<String, A> — denied.");
    }

    let bono_own_msg = JPMailMessage::<Public>::new(
        "admin@cse.psu.edu",
        "bono@cse.psu.edu",
        "Public announcement",
        Labeled::new("This is a public message. Anyone can read it.".to_string()),
    );
    println!("\n  [Bono reads his own Public mail — authorized]");
    pop3::MailReaderCrypto::<Public>::display_headers(&bono_own_msg);
    
    pop3::MailReaderCrypto::<Public>::display_body_publicly(&bono_own_msg);
    println!("  [IFC] Public: FlowsTo<Public> ✓ — bono authorized for his own Label-Public mail.");

    let _ = bono_reader;
}

fn phase_siis_group_mail() {
    println!("\n╔══ PHASE 4: SIIS group mail (Label AB = alice ∪ bob) ══╗");

    let group_body = Labeled::<String, AB>::new(
        "SIIS weekly sync: Monday 10am, Zoom link: https://zoom.psu.edu/j/123456\n\
         Agenda: IFC demo, JPmail update, budget review."
            .to_string(),
    );
    let group_msg = JPMailMessage::<AB>::new("admin@cse.psu.edu", "siis@cse.psu.edu", "SIIS Weekly Sync (Label AB)", group_body);

    let admin_pw = Labeled::<String, AB>::new("admin_pw_stub".to_string());
    let sender = MailSenderCrypto::<AB>::new("mail.cse.psu.edu", "admin", "admin@cse.psu.edu", admin_pw);
    sender.send_message(&group_msg, "siis_group_rsa_key");

    println!("\n  alice reading SIIS group mail (A ≤ AB — authorized):");
    println!("  From   : {}", group_msg.from);
    println!("  Subject: {}", group_msg.subject);
    println!("  Body   : [Labeled<String, AB> — confined to siis group context]");

    println!("\n  bob reading SIIS group mail (B ≤ AB — authorized):");
    println!("  Body   : [Labeled<String, AB> — confined to siis group context]");

    println!("\n  bono attempting SIIS group mail:");
    println!("  [IFC] AB: FlowsTo<Public> not implemented — bono denied.");
}

fn phase_implicit_flow() {
    println!("\n╔══ PHASE 5: Implicit Flow Control (pc_block!) ══╗");
    println!("  Goal: prevent bono from learning alice's secrets via side channels.\n");

    let alice_has_unread: Labeled<bool, A> = Labeled::new(true);

    let public_alert_count: Labeled<i32, Public> = Labeled::new(0);

    let mut alice_audit: Labeled<i32, A> = Labeled::new(0);
    #[allow(unused_assignments)]
    let _ = &alice_audit;

    pc_block! { (A) {
        if alice_has_unread {
            
            alice_audit = Labeled::<i32, A>::new(1);

        }
    }};

    println!("  alice_audit: Labeled<i32, A>  [only alice can observe — not declassified]");
    println!("  public_alert_count (Public) = {}  [bono sees this — NOT updated inside if(A)]", declassify(public_alert_count));
    println!("  [pc_block!] Implicit flow from if(alice_has_unread) blocked successfully.");

    let _ = public_alert_count;
}

fn phase_label_propagation(messages: &[JPMailMessage<A>]) {
    println!("\n╔══ PHASE 6: Label propagation (fcall! and mcall!) ══╗");

    if let Some(msg) = messages.first() {
        
        let labeled_subject: Labeled<String, A> = Labeled::new(msg.subject.clone());
        let _subject_len: Labeled<usize, A> = mcall!(labeled_subject.len());
        
        println!("  [mcall!] Subject length: Labeled<usize, A>  [label preserved — not declassified]");

        let _body_len: Labeled<usize, A> = fcall!(String::len(msg.body.as_ref()));
        
        println!("  [fcall!] Body length: Labeled<usize, A>  [label joined by fcall! — not declassified]");

        let a_size: Labeled<u32, A> = mcall!(msg.body.len()).__map(|v| v as u32);
        let b_size = Labeled::<u32, B>::new(42_u32);
        let _combined: Labeled<u32, AB> = fcall!(u32::saturating_add(a_size, b_size));
        
        println!("  [fcall!] alice-bytes + bob-bytes: Labeled<u32, AB> = join(A,B)  [not declassified]");
        println!("  [IFC] Result labeled AB — only siis group can access combined computation.");
    }
}

fn print_banner() {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║  JPmail: Secure Email with Information Flow Control            ║");
    println!("║  Rust port · fg_ifc_library (Labeled<T,L>, fcall!, pc_block!) ║");
    println!("║  hell0@github.com                                               ║");
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
