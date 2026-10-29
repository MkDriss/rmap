//! Point d'entrée du scanner : lit les arguments, lance le scan, affiche le bilan.
//! Toute la logique est dans la bibliothèque (`lib.rs`, `targets.rs`, `ports.rs`, `scan.rs`).

use std::net::IpAddr;
use std::time::Duration;

use clap::Parser;

use rmap::ports::parse_ports;
use rmap::scan::{PortState, discover_hosts, scan_targets};
use rmap::targets::parse_targets;

/// Scanner de ports TCP simple (inspiré de nmap)
#[derive(Parser)]
#[command(name = "rmap", about = "Scanner de ports TCP")]
struct Args {
    /// Cible(s) : IP, plage (192.168.1.1-50) ou bloc CIDR (192.168.1.0/24),
    /// plusieurs séparées par des virgules
    #[arg(
        short = 't',
        long = "target",
        default_value = "127.0.0.1",
        allow_hyphen_values = true
    )]
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
    #[arg(long = "timeout-ms", default_value_t = 1500)]
    timeout_ms: u64,

    /// Repère d'abord les machines vivantes et ne scanne que celles-là
    #[arg(long = "discover", default_value_t = false)]
    discover: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // ---------- 1. Vérifier les arguments ----------

    let ips = match parse_targets(&args.target) {
        Ok(ips) => ips,
        Err(e) => {
            eprintln!("Cible invalide : {e}");
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

    let delay = Duration::from_millis(args.timeout_ms);

    // ---------- 2. Découverte d'hôtes (optionnelle) ----------

    let ips = if args.discover {
        println!("Découverte sur {} machine(s)...", ips.len());
        let vivantes = discover_hosts(ips, args.concurrency, delay).await;
        println!("{} machine(s) vivante(s) :", vivantes.len());
        for ip in &vivantes {
            println!("  {ip}");
        }
        if vivantes.is_empty() {
            return; // rien à scanner
        }
        vivantes
    } else {
        ips
    };

    // ---------- 3. Lancer le scan ----------

    let nb_ports = ports.len();
    let multi = ips.len() > 1; // affichage un peu différent pour plusieurs machines
    println!("\nScan de {} machine(s) sur {nb_ports} port(s)", ips.len());

    let results = scan_targets(ips, ports, args.concurrency, delay).await;

    // ---------- 4. Afficher le bilan, groupé par machine ----------

    for (ip, states) in results {
        afficher_hote(ip, &states, nb_ports, multi);
    }
}

/// Affiche le résultat d'une seule machine : ses ports ouverts, puis son bilan.
fn afficher_hote(ip: IpAddr, states: &[(u16, PortState)], nb_ports: usize, multi: bool) {
    let mut open = Vec::new();
    let mut closed = 0u32;
    let mut filtered = 0u32;
    let mut errors: Vec<(u16, &str)> = Vec::new();

    // states est déjà trié par port (scan_ports s'en est chargé).
    for (port, state) in states {
        match state {
            PortState::Open => open.push(*port),
            PortState::Closed => closed += 1,
            PortState::Filtered => filtered += 1,
            PortState::Error(msg) => errors.push((*port, msg)),
        }
    }

    // Ports sans résultat : leur tâche a échoué (voir scan_ports).
    let missing = nb_ports - states.len();

    // Avec plusieurs machines, on n'affiche une section que si elle a quelque chose
    // à montrer, pour ne pas noyer l'écran sous les hôtes sans port ouvert.
    if multi && open.is_empty() && errors.is_empty() && missing == 0 {
        return;
    }

    println!("\n=== {ip} ===");
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
    if missing > 0 {
        eprintln!("⚠ Résultats incomplets : {missing} port(s) sans résultat (tâche en échec).");
    }
}
