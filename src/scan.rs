//! Scan TCP « connect » : on tente une vraie connexion sur chaque port.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;

/// État d'un port vu par le scanner (vocabulaire inspiré de nmap).
#[derive(Debug, PartialEq)]
pub enum PortState {
    /// La connexion a abouti : un service écoute.
    Open,
    /// L'hôte a refusé la connexion (ECONNREFUSED) : personne n'écoute.
    Closed,
    /// Aucune réponse avant le timeout : probablement filtré par un pare-feu.
    Filtered,
    /// Erreur qui empêche de conclure (ex. plus de descripteurs de fichiers).
    Error(String),
}

/// Tente une connexion TCP complète sur `addr`, en abandonnant après `delay`.
pub async fn scan_port(addr: SocketAddr, delay: Duration) -> PortState {
    match timeout(delay, TcpStream::connect(addr)).await {
        // Niveau 1 = résultat du timeout ; niveau 2 = résultat de connect.
        Ok(Ok(_stream)) => PortState::Open,
        Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionRefused => PortState::Closed,
        Ok(Err(e)) => PortState::Error(e.to_string()),
        Err(_elapsed) => PortState::Filtered,
    }
}

/// Scanne tous les `ports` de `ip`, avec au plus `concurrency` connexions en même temps.
/// Renvoie l'état de chaque port, trié par numéro de port.
///
/// Si la tâche d'un port échoue (panique), l'échec est signalé sur la sortie
/// d'erreur et le scan continue : ce port est alors absent des résultats.
///
/// # Panics
///
/// Panique si `concurrency` vaut 0 : sans permis, le sémaphore bloquerait le scan pour toujours.
pub async fn scan_ports(
    ip: IpAddr,
    ports: Vec<u16>,
    concurrency: usize,
    delay: Duration,
) -> Vec<(u16, PortState)> {
    assert!(concurrency > 0, "concurrency doit valoir au moins 1");

    // Arc = pointeur partagé à comptage de références, utilisable entre threads.
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut tasks = JoinSet::new();

    for port in ports {
        // Attend qu'une place se libère si `concurrency` tâches tournent déjà.
        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("le sémaphore n'est jamais fermé");
        let socket_addr = SocketAddr::new(ip, port);

        tasks.spawn(async move {
            let state = scan_port(socket_addr, delay).await;
            drop(permit); // rend la place au sémaphore
            (port, state) // on renvoie le port ET son état
        });
    }

    // Récupère les résultats au fur et à mesure que les tâches se terminent.
    let mut results = Vec::new();
    while let Some(res) = tasks.join_next().await {
        match res {
            Ok(port_and_state) => results.push(port_and_state),
            // Une tâche a paniqué (ce serait un bug) : on le signale et le scan continue.
            Err(e) => eprintln!("Une tâche a échoué : {e}"),
        }
    }

    // Les tâches finissent dans le désordre : on remet les ports dans l'ordre.
    results.sort_unstable_by_key(|(port, _)| *port);
    results
}

/// Ports testés pour savoir si une machine est vivante (découverte d'hôtes).
/// Ce sont des ports courants, dont le dernier (1883) est le MQTT du labo.
const PROBE_PORTS: [u16; 7] = [22, 80, 443, 445, 3389, 8080, 1883];

/// Scanne plusieurs machines sur plusieurs ports, toutes connexions confondues
/// dans un seul pool de `concurrency` connexions simultanées. Une machine lente
/// ou absente ne bloque donc plus les autres.
///
/// Renvoie, pour chaque IP et dans l'ordre reçu, la liste de ses ports triée.
///
/// # Panics
///
/// Panique si `concurrency` vaut 0 (voir `scan_ports`).
pub async fn scan_targets(
    ips: Vec<IpAddr>,
    ports: Vec<u16>,
    concurrency: usize,
    delay: Duration,
) -> Vec<(IpAddr, Vec<(u16, PortState)>)> {
    assert!(concurrency > 0, "concurrency doit valoir au moins 1");

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut tasks = JoinSet::new();

    // Une tâche par couple (machine, port) : tout part dans le même pool.
    for &ip in &ips {
        for &port in &ports {
            let permit = semaphore
                .clone()
                .acquire_owned()
                .await
                .expect("le sémaphore n'est jamais fermé");
            // `ip` et `port` sont Copy : le `move` les recopie, pas besoin de clone.
            tasks.spawn(async move {
                let state = scan_port(SocketAddr::new(ip, port), delay).await;
                drop(permit);
                (ip, port, state)
            });
        }
    }

    // On regroupe les résultats par machine dans une table.
    let mut par_ip: HashMap<IpAddr, Vec<(u16, PortState)>> = HashMap::new();
    while let Some(res) = tasks.join_next().await {
        match res {
            Ok((ip, port, state)) => par_ip.entry(ip).or_default().push((port, state)),
            Err(e) => eprintln!("Une tâche a échoué : {e}"),
        }
    }

    // On reconstruit la liste dans l'ordre des IP reçues, chaque bloc trié par port.
    let mut out = Vec::with_capacity(ips.len());
    for ip in ips {
        let mut states = par_ip.remove(&ip).unwrap_or_default();
        states.sort_unstable_by_key(|(port, _)| *port);
        out.push((ip, states));
    }
    out
}

/// Découverte d'hôtes : renvoie, parmi `ips`, celles qui semblent vivantes.
///
/// Sans privilèges, on ne peut pas envoyer de ping ICMP. On considère donc
/// qu'une machine est vivante si elle **répond** sur au moins un des ports testés :
/// un port ouvert OU fermé prouve qu'elle est joignable (un port fermé renvoie un
/// refus de connexion). Une machine totalement filtrée par un pare-feu, ou absente,
/// ne répond sur aucun port et sera considérée comme éteinte.
///
/// # Panics
///
/// Panique si `concurrency` vaut 0 (voir `scan_ports`).
pub async fn discover_hosts(ips: Vec<IpAddr>, concurrency: usize, delay: Duration) -> Vec<IpAddr> {
    assert!(concurrency > 0, "concurrency doit valoir au moins 1");

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut tasks = JoinSet::new();

    for &ip in &ips {
        for &port in &PROBE_PORTS {
            let permit = semaphore
                .clone()
                .acquire_owned()
                .await
                .expect("le sémaphore n'est jamais fermé");
            tasks.spawn(async move {
                let state = scan_port(SocketAddr::new(ip, port), delay).await;
                drop(permit);
                // `matches!` : vrai si `state` correspond à l'un des motifs donnés.
                let vivant = matches!(state, PortState::Open | PortState::Closed);
                (ip, vivant)
            });
        }
    }

    // Un HashSet évite les doublons : plusieurs ports d'une même machine peuvent répondre.
    let mut vivantes = HashSet::new();
    while let Some(res) = tasks.join_next().await {
        match res {
            Ok((ip, true)) => {
                vivantes.insert(ip);
            }
            Ok((_, false)) => {}
            Err(e) => eprintln!("Une tâche a échoué : {e}"),
        }
    }

    let mut out: Vec<IpAddr> = vivantes.into_iter().collect();
    out.sort_unstable();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn port_ouvert_detecte() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        assert_eq!(
            scan_port(addr, Duration::from_secs(1)).await,
            PortState::Open
        );
    }

    #[tokio::test]
    async fn port_ferme_detecte() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        assert_eq!(
            scan_port(addr, Duration::from_secs(1)).await,
            PortState::Closed
        );
    }

    #[tokio::test]
    async fn scan_ports_renvoie_les_etats_tries() {
        // Un port ouvert (listener actif) et un port fermé (listener détruit).
        let ouvert = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port_ouvert = ouvert.local_addr().unwrap().port();
        let ferme = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port_ferme = ferme.local_addr().unwrap().port();
        drop(ferme);

        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        // On passe les ports dans le désordre pour vérifier le tri.
        let ports = vec![port_ouvert.max(port_ferme), port_ouvert.min(port_ferme)];
        let results = scan_ports(ip, ports, 10, Duration::from_secs(1)).await;

        assert_eq!(results.len(), 2);
        assert!(results[0].0 < results[1].0, "résultats non triés");
        assert!(results.contains(&(port_ouvert, PortState::Open)));
        assert!(results.contains(&(port_ferme, PortState::Closed)));
    }

    #[tokio::test]
    async fn scan_targets_groupe_et_ordonne() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let results = scan_targets(vec![ip], vec![port], 10, Duration::from_secs(1)).await;

        // Une IP demandée -> une entrée en sortie, avec son port ouvert.
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, ip);
        assert_eq!(results[0].1, vec![(port, PortState::Open)]);
    }

    #[tokio::test]
    async fn discover_trouve_une_machine_qui_repond() {
        // 127.0.0.1 répond toujours (ports fermés -> refus de connexion),
        // donc la découverte doit la voir comme vivante.
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let vivantes = discover_hosts(vec![ip], 10, Duration::from_secs(1)).await;
        assert!(vivantes.contains(&ip));
    }
}