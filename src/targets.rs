//! Lecture d'une ou plusieurs cibles : IP seule, plage, ou bloc CIDR.
//!
//! Formes acceptées (séparées par des virgules) :
//! - une IP : `192.168.50.10`, `::1`
//! - une plage sur le dernier octet : `192.168.50.1-50`
//! - un bloc CIDR : `192.168.50.0/24`
//!
//! Les plages et le CIDR ne concernent que l'IPv4. Une IPv6 n'est acceptée
//! que sous la forme d'une adresse seule.

use std::net::{IpAddr, Ipv4Addr};

/// Nombre maximal d'adresses qu'un seul bloc CIDR peut produire (préfixe >= /16).
const MAX_CIDR_HOSTS: u32 = 65_536;

/// Convertit une liste de cibles en liste d'adresses IP, triées et sans doublons.
pub fn parse_targets(spec: &str) -> Result<Vec<IpAddr>, String> {
    let mut ips = Vec::new();

    // Même découpage que pour les ports : on sépare sur les virgules.
    for token in spec.split(',') {
        let token = token.trim();
        if token.is_empty() {
            return Err(format!("élément vide dans « {spec} »"));
        }

        if token.contains('/') {
            ips.extend(parse_cidr(token)?);
        } else if token.contains('-') {
            ips.extend(parse_range(token)?);
        } else {
            // IP seule : IPv4 ou IPv6.
            let ip = token
                .parse::<IpAddr>()
                .map_err(|e| format!("adresse invalide « {token} » : {e}"))?;
            ips.push(ip);
        }
    }

    // Les IpAddr sont ordonnables et comparables : on trie et on retire les doublons.
    ips.sort_unstable();
    ips.dedup();
    Ok(ips)
}

/// Développe un bloc CIDR IPv4, par exemple "192.168.50.0/24".
fn parse_cidr(token: &str) -> Result<Vec<IpAddr>, String> {
    // split_once coupe au premier '/' : "192.168.50.0" et "24".
    let (ip_part, prefix_part) = token
        .split_once('/')
        .ok_or_else(|| format!("CIDR invalide « {token} »"))?;

    let ip = ip_part
        .parse::<Ipv4Addr>()
        .map_err(|e| format!("adresse IPv4 invalide « {ip_part} » : {e}"))?;
    let prefix = prefix_part
        .parse::<u8>()
        .map_err(|e| format!("préfixe invalide « {prefix_part} » : {e}"))?;

    if prefix > 32 {
        return Err(format!("préfixe /{prefix} invalide (max /32)"));
    }
    let host_bits = 32 - prefix;

    // Décaler un u32 de 32 bits est interdit : on traite /0 à part. De toute façon,
    // la limite ci-dessous refuse déjà tout bloc aussi grand.
    let count = if host_bits >= 32 {
        u32::MAX // valeur volontairement énorme pour déclencher le refus suivant
    } else {
        1u32 << host_bits
    };
    if count > MAX_CIDR_HOSTS {
        return Err(format!(
            "bloc « {token} » trop grand ({count} adresses, limite {MAX_CIDR_HOSTS})"
        ));
    }

    // Masque réseau : on remet à zéro les bits d'hôte, pour accepter "…​.37/24".
    let mask = if host_bits == 32 {
        0
    } else {
        u32::MAX << host_bits
    };
    let network = u32::from(ip) & mask;

    // Toutes les adresses du bloc, y compris l'adresse réseau (.0) et de diffusion (.255).
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count {
        out.push(IpAddr::V4(Ipv4Addr::from(network + i)));
    }
    Ok(out)
}

/// Développe une plage sur le dernier octet IPv4, par exemple "192.168.50.1-50".
fn parse_range(token: &str) -> Result<Vec<IpAddr>, String> {
    // On isole le dernier octet : "192.168.50" et "1-50".
    let (head, last) = token
        .rsplit_once('.')
        .ok_or_else(|| format!("plage invalide « {token} »"))?;
    let (start, end) = last
        .split_once('-')
        .ok_or_else(|| format!("plage invalide « {token} »"))?;

    let start: u8 = start
        .parse()
        .map_err(|e| format!("début de plage invalide « {start} » : {e}"))?;
    let end: u8 = end
        .parse()
        .map_err(|e| format!("fin de plage invalide « {end} » : {e}"))?;
    if start > end {
        return Err(format!("plage inversée « {token} »"));
    }

    let mut out = Vec::new();
    for octet in start..=end {
        // On reconstruit l'adresse et on la fait valider par le parseur standard,
        // ce qui vérifie du même coup les trois premiers octets.
        let ip = format!("{head}.{octet}")
            .parse::<Ipv4Addr>()
            .map_err(|e| format!("adresse invalide « {head}.{octet} » : {e}"))?;
        out.push(IpAddr::V4(ip));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ips(spec: &str) -> Vec<String> {
        parse_targets(spec)
            .unwrap()
            .into_iter()
            .map(|ip| ip.to_string())
            .collect()
    }

    #[test]
    fn ip_seule_v4_et_v6() {
        assert_eq!(ips("192.168.50.10"), ["192.168.50.10"]);
        assert_eq!(ips("::1"), ["::1"]);
    }

    #[test]
    fn plage_dernier_octet() {
        assert_eq!(
            ips("192.168.50.1-3"),
            ["192.168.50.1", "192.168.50.2", "192.168.50.3"]
        );
    }

    #[test]
    fn cidr() {
        let v = parse_targets("192.168.50.0/24").unwrap();
        assert_eq!(v.len(), 256);
        assert_eq!(v[0].to_string(), "192.168.50.0");
        assert_eq!(v[255].to_string(), "192.168.50.255");

        // Un /32 ne contient qu'une adresse.
        assert_eq!(ips("10.0.0.5/32"), ["10.0.0.5"]);

        // Les bits d'hôte sont ignorés : .37/24 == .0/24.
        assert_eq!(parse_targets("192.168.50.37/24").unwrap().len(), 256);
    }

    #[test]
    fn listes_et_dedoublonnage() {
        // La virgule combine les formes ; les doublons et l'ordre sont normalisés.
        assert_eq!(
            ips("192.168.50.3,192.168.50.1,192.168.50.1-2"),
            ["192.168.50.1", "192.168.50.2", "192.168.50.3"]
        );
    }

    #[test]
    fn entrees_invalides() {
        let invalides = [
            "",
            "abc",
            "256.0.0.1",
            "192.168.50.1-300", // 300 n'est pas un octet
            "192.168.50.50-1",  // inversée
            "10.0.0.0/8",       // bloc trop grand
            "10.0.0.0/33",      // préfixe impossible
            "192.168.50.,80",   // élément vide
        ];
        for spec in invalides {
            assert!(
                parse_targets(spec).is_err(),
                "« {spec} » aurait dû être refusé"
            );
        }
    }
}