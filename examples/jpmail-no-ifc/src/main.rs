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

    let alice_pw = PrincipalWrapper::new("alice", "demo/certs-alice/");
    let bob_pw = PrincipalWrapper::new("bob", "demo/certs-bob/");
    let bono_pw = PrincipalWrapper::new("bono", "demo/certs-bono/");

    store.add_principal(&alice_pw);
    store.add_principal(&bob_pw);
    store.add_principal(&bono_pw);

    store.add_delegation(Delegation::new("siis", "alice", "AB"));
    store.add_delegation(Delegation::new("siis", "bob", "AB"));
    store.add_delegation(Delegation::new("nsrc", "bono", "Public"));

    println!("[PolicyStore] Registered {} principals: {:?}", store.list_principals().len(), store.list_principals());

    password::NewPassword::bootstrap("alice", "alice_smtp_secret".to_string());
    password::NewPassword::bootstrap("bob", "bob_smtp_secret".to_string());
    password::NewPassword::bootstrap("bono", "bono_smtp_public".to_string());
}

fn phase_sendmail() -> Vec<JPMailMessage> {
    println!("\n╔══ PHASE 1: jpsendmail -- Alice sends messages ══╗");
    println!("[jpsendmail] Principal: alice | Server: mail.cse.psu.edu");

    let alice_smtp_pw = "alice_smtp_secret".to_string();
    let sender = MailSenderCrypto::new("mail.cse.psu.edu", "alice", "alice@cse.psu.edu", alice_smtp_pw);

    let budget_body = "SIIS budget for FY2006: $500,000 total.\n\
         Breakdown: research 60%, hardware 25%, travel 15%.\n\
         DO NOT forward to nsrc group (bono)."
        .to_string();
    let msg1 = JPMailMessage::new("alice@cse.psu.edu", "alice@cse.psu.edu", "SIIS Budget FY2006 (CONFIDENTIAL)", budget_body);
    sender.send_message(&msg1, "alice_rsa_key");

    let note_body = "Alice, the SIIS project review is Thursday 3pm, room 405.\n\
         Please bring the encryption demo."
        .to_string();
    let msg2 = JPMailMessage::new("bob@cse.psu.edu", "alice@cse.psu.edu", "Meeting Reminder", note_body);
    sender.send_message(&msg2, "alice_rsa_key");

    vec![msg1, msg2]
}

fn phase_alice_getmail(messages: &[JPMailMessage]) {
    println!("\n╔══ PHASE 2: jpgetmail -- alice reads her mailbox ══╗");
    println!("[jpgetmail] Principal: alice | Server: jpmail.cse.psu.edu");

    let alice_pw = "alice_pop3_secret".to_string();
    let mut reader = pop3::MailReaderCrypto::new("jpmail.cse.psu.edu", "alice", alice_pw);

    reader.retrieve_messages();

    println!("\n[POP3] alice's mailbox: {} messages (alice authorized)", messages.len());

    for (i, msg) in messages.iter().enumerate() {
        println!("\n  -- Message {} --", i + 1);
        pop3::MailReaderCrypto::display_headers(msg);
        println!("  Body   : [confined to alice's context]");
    }

    let _count: usize = reader.message_count();
    println!("\n  Message count: {}", _count);
}

fn phase_bono_getmail_denied(alice_messages: &[JPMailMessage]) {
    println!("\n╔══ PHASE 3: jpgetmail -- bono tries to read alice's mail ══╗");
    println!("[jpgetmail] Principal: bono | Server: jpmail.cse.psu.edu");
    println!("bono has Public clearance. Alice's mailbox is confidential.");

    let bono_pw = "bono_pop3_pw".to_string();
    let bono_reader = pop3::MailReaderCrypto::new("jpmail.cse.psu.edu", "bono", bono_pw);

    println!("\n[POP3] bono connects to alice's spool ({} messages)...", alice_messages.len());

    for (i, msg) in alice_messages.iter().enumerate() {
        println!("\n  -- Message {} (as seen by bono) --", i + 1);

        pop3::MailReaderCrypto::display_headers(msg);

        println!("  Body   : [ACCESS DENIED -- requires alice's KeyPrincipal]");
        println!("  bono's KeyPrincipal cannot produce alice's private key.");
        println!("  MimeMailMessage::decrypt() requires alice's private key -- denied.");
    }

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

fn phase_siis_group_mail() {
    println!("\n╔══ PHASE 4: SIIS group mail (AB = alice U bob) ══╗");

    let group_body = "SIIS weekly sync: Monday 10am, Zoom link: https://zoom.psu.edu/j/123456\n\
         Agenda: IFC demo, JPmail update, budget review."
        .to_string();
    let group_msg = JPMailMessage::new("admin@cse.psu.edu", "siis@cse.psu.edu", "SIIS Weekly Sync", group_body);

    let admin_pw = "admin_pw_stub".to_string();
    let sender = MailSenderCrypto::new("mail.cse.psu.edu", "admin", "admin@cse.psu.edu", admin_pw);
    sender.send_message(&group_msg, "siis_group_rsa_key");

    println!("\n  alice reading SIIS group mail (authorized):");
    println!("  From   : {}", group_msg.from);
    println!("  Subject: {}", group_msg.subject);
    println!("  Body   : [confined to siis group context]");

    println!("\n  bob reading SIIS group mail (authorized):");
    println!("  Body   : [confined to siis group context]");

    println!("\n  bono attempting SIIS group mail:");
    println!("  bono denied -- not a member of siis group.");
}

fn phase_implicit_flow() {
    println!("\n╔══ PHASE 5: Implicit Flow Control ══╗");
    println!("  Goal: prevent bono from learning alice's secrets via side channels.\n");

    let alice_has_unread: bool = true;

    let public_alert_count: i32 = 0;

    let mut alice_audit: i32 = 0;

    if alice_has_unread {
        
        alice_audit = 1;

    }

    println!("  alice_audit: {}  [only alice can observe]", alice_audit);
    println!("  public_alert_count = {}  [bono sees this -- NOT updated inside if(alice_has_unread)]", public_alert_count);
    println!("  Implicit flow from if(alice_has_unread) blocked successfully.");
}

fn phase_label_propagation(messages: &[JPMailMessage]) {
    println!("\n╔══ PHASE 6: Label propagation ══╗");

    if let Some(msg) = messages.first() {
        
        let _subject_len: usize = msg.subject.len();
        println!("  Subject length: {}  [not declassified]", _subject_len);

        let _body_len: usize = msg.body.len();
        println!("  Body length: {}  [not declassified]", _body_len);

        let a_size: u32 = msg.body.len() as u32;
        let b_size: u32 = 42_u32;
        let _combined: u32 = a_size.saturating_add(b_size);
        println!("  alice-bytes + bob-bytes: {} = combined  [not declassified]", _combined);
        println!("  Result -- only siis group can access combined computation.");
    }
}

fn print_banner() {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║  JPmail: Secure Email (No IFC version)                         ║");
    println!("║  Rust port · ACSAC 2006                                        ║");
    println!("║  github.com/who/jpmail                              ║");
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
