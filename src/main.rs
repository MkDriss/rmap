//! Point d'entrée du scanner : lit les arguments, lance le scan, affiche le bilan.
//! Toute la logique est dans la bibliothèque (`lib.rs`, `ports.rs`, `scan.rs`).

use std::net::IpAddr;
use std::time::Duration;

use clap::Parser;

// `scanner` est le nom de notre propre bibliothèque (le nom du package dans Cargo.toml).
use scanner::ports::parse_ports;
use scanner::scan::{PortState, scan_ports};

/// Scanner de ports TCP simple (inspiré de nmap)
#[derive(Parser)]
#[command(name = "scanner", about = "Scanner de ports TCP")]
struct Args {
    /// Adresse IP à scanner (IPv4 ou IPv6)
    #[arg(short = 't', long = "target", default_value = "127.0.0.1")]
    target: String,

    /// Ports à scanner, syntaxe nmap : 22,80,443 | 1-1024 | -100 | 60000- | -
    #[arg(
        short = 'p',
        long = "ports",
        default_value = "1-1024",
        allow_hyphen_values = true
    )]
    ports: String,

    /// Nombre maximal de connexions ouvertes en même temps
    #[arg(short = 'c', long = "concurrency", default_value_t = 500)]
    concurrency: usize,

    /// Délai maximal par tentative de connexion, en millisecondes
    #[arg(short = 'T', long = "timeout-ms", default_value_t = 1500)]
    timeout_ms: u64,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // ---------- 1. Vérifier les arguments ----------

    let ip = match args.target.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(e) => {
            eprintln!("Adresse IP invalide « {} » : {e}", args.target);
            std::process::exit(1);
        }
    };

    let ports = match parse_ports(&args.ports) {
        Ok(ports) => ports,
        Err(e) => {
            eprintln!("Ports invalides : {e}");
            std::process::exit(1);
        }
    };

    // On vérifie ici pour afficher un message clair, au lieu de laisser scan_ports paniquer.
    if args.concurrency == 0 {
        eprintln!("--concurrency doit valoir au moins 1");
        std::process::exit(1);
    }

    // ---------- 2. Lancer le scan ----------

    // On note le nombre de ports AVANT l'appel : scan_ports va consommer `ports`.
    let nb_ports = ports.len();
    println!("Scan de {ip} : {nb_ports} port(s) à tester");

    let delay = Duration::from_millis(args.timeout_ms);
    let results = scan_ports(ip, ports, args.concurrency, delay).await;

    // Un port dont la tâche a échoué n'a pas de résultat (voir scan_ports).
    // Il y a au plus un résultat par port, donc cette soustraction ne peut pas être négative.
    let missing = nb_ports - results.len();

    // ---------- 3. Afficher le bilan ----------

    let mut open = Vec::new();
    let mut closed = 0u32;
    let mut filtered = 0u32;
    let mut errors: Vec<(u16, String)> = Vec::new();

    // `results` est déjà trié par port : pas besoin de retrier.
    for (port, state) in results {
        match state {
            PortState::Open => open.push(port),
            PortState::Closed => closed += 1,
            PortState::Filtered => filtered += 1,
            PortState::Error(msg) => errors.push((port, msg)),
        }
    }

    for port in &open {
        println!("Port {port} : OUVERT");
    }
    println!(
        "{} ouvert(s), {closed} fermé(s), {filtered} filtré(s), {} erreur(s)",
        open.len(),
        errors.len()
    );

    // On ne cache pas les erreurs : un résultat incomplet doit se voir.
    if !errors.is_empty() {
        eprintln!(
            "⚠ Résultats incomplets : {} port(s) n'ont pas pu être testés.",
            errors.len()
        );
        for (port, msg) in errors.iter().take(5) {
            eprintln!("  port {port} : {msg}");
        }
    }

    // Ports sans aucun résultat : leur tâche a échoué (message « Une tâche a échoué » plus haut).
    if missing > 0 {
        eprintln!("⚠ Résultats incomplets : {missing} port(s) sans résultat (tâche en échec).");
    }
}