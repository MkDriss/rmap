//! Scan TCP « connect » : on tente une vraie connexion sur chaque port.

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

/// Scanne plusieurs adresses, l'une après l'autre. Chaque hôte est scanné avec
/// jusqu'à `concurrency` connexions simultanées (la limite vaut donc par hôte).
///
/// Renvoie, pour chaque IP et dans l'ordre reçu, la liste de ses ports avec leur état.
pub async fn scan_targets(
    ips: Vec<IpAddr>,
    ports: Vec<u16>,
    concurrency: usize,
    delay: Duration,
) -> Vec<(IpAddr, Vec<(u16, PortState)>)> {
    let mut out = Vec::with_capacity(ips.len());
    for ip in ips {
        // `ports.clone()` : chaque hôte a besoin de sa propre copie de la liste,
        // car scan_ports consomme le vecteur qu'on lui passe.
        let states = scan_ports(ip, ports.clone(), concurrency, delay).await;
        out.push((ip, states));
    }
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
}