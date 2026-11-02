//! Résolution DNS inverse : retrouver le nom d'une machine à partir de son adresse IP,
//! comme le fait nmap pour les machines qu'il trouve en ligne.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use tokio::task::JoinSet;
use tokio::time::timeout;

/// Cherche le nom associé à `ip` (enregistrement DNS « PTR » ou fichier /etc/hosts),
/// en abandonnant après `delay`. Renvoie `None` si aucun nom n'est trouvé à temps.
pub async fn reverse_lookup(ip: IpAddr, delay: Duration) -> Option<String> {
    // `lookup_addr` appelle la fonction système getnameinfo, qui est BLOQUANTE :
    // elle fige le thread qui l'appelle. On l'exécute donc sur un thread à part,
    // réservé aux tâches bloquantes, pour ne pas immobiliser le runtime tokio.
    let task = tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip));

    match timeout(delay, task).await {
        // 3 niveaux : délai respecté / thread terminé sans panique / nom trouvé.
        Ok(Ok(Ok(name))) => Some(name),
        // Pas de nom, erreur de résolution, panique ou délai dépassé : on n'affiche rien.
        _ => None,
    }
}

/// Résout les noms de plusieurs adresses en parallèle.
/// Seules les adresses pour lesquelles un nom a été trouvé figurent dans la table.
pub async fn resolve_names(ips: &[IpAddr], delay: Duration) -> HashMap<IpAddr, String> {
    let mut tasks = JoinSet::new();
    for &ip in ips {
        tasks.spawn(async move { (ip, reverse_lookup(ip, delay).await) });
    }

    let mut names = HashMap::new();
    while let Some(res) = tasks.join_next().await {
        // `if let` : on ne garde que le cas qui nous intéresse, un nom trouvé.
        if let Ok((ip, Some(name))) = res {
            names.insert(ip, name);
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn localhost_a_un_nom() {
        // Sur Linux, /etc/hosts associe 127.0.0.1 au nom « localhost ».
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let name = reverse_lookup(ip, Duration::from_secs(2)).await;
        assert!(name.is_some(), "127.0.0.1 devrait avoir un nom");
    }

    #[tokio::test]
    async fn adresse_de_documentation_sans_nom() {
        // 192.0.2.0/24 est réservé à la documentation (RFC 5737) : aucun nom attendu.
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        assert_eq!(reverse_lookup(ip, Duration::from_secs(2)).await, None);
    }
}