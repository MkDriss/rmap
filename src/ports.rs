//! Lecture d'une liste de ports écrite avec la syntaxe de nmap.

/// Convertit une liste de ports façon nmap en liste triée, sans doublons.
/// Formes acceptées : "22", "22,80,443", "1-1024", "-100", "60000-", "-".
pub fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();

    // On découpe sur les virgules : "22,80-90" -> "22" puis "80-90".
    for token in spec.split(',') {
        let token = token.trim();
        if token.is_empty() {
            return Err(format!("élément vide dans « {spec} »"));
        }

        match token.split_once('-') {
            // Pas de tiret : un port seul.
            None => ports.push(parse_port(token)?),

            // Un tiret : une plage. Une borne vide veut dire 1 (début) ou 65535 (fin).
            Some((start, end)) => {
                let start = if start.is_empty() {
                    1
                } else {
                    parse_port(start)?
                };
                let end = if end.is_empty() {
                    65535
                } else {
                    parse_port(end)?
                };

                if start > end {
                    return Err(format!("plage inversée « {token} »"));
                }
                for port in start..=end {
                    ports.push(port);
                }
            }
        }
    }

    // `dedup` ne retire que les doublons qui se suivent : il faut donc trier d'abord.
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

/// Convertit un seul numéro de port (entre 1 et 65535).
/// Fonction privée (pas de `pub`) : elle ne sert qu'à `parse_ports`.
fn parse_port(text: &str) -> Result<u16, String> {
    // Le type u16 refuse déjà tout ce qui dépasse 65535 (ou qui n'est pas un nombre).
    let port = match text.trim().parse::<u16>() {
        Ok(port) => port,
        Err(e) => return Err(format!("port invalide « {text} » : {e}")),
    };

    // Choix de conception : nmap accepte le port 0 s'il est explicite, pas nous.
    if port == 0 {
        return Err("le port 0 est refusé".to_string());
    }
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_isoles_et_listes() {
        assert_eq!(parse_ports("22"), Ok(vec![22]));
        assert_eq!(parse_ports("443,22,80"), Ok(vec![22, 80, 443])); // trié
        assert_eq!(parse_ports("22,22,22"), Ok(vec![22])); // sans doublons
        assert_eq!(parse_ports(" 22 , 80 "), Ok(vec![22, 80])); // espaces tolérés
    }

    #[test]
    fn plages_et_bornes_omises() {
        assert_eq!(parse_ports("20-23"), Ok(vec![20, 21, 22, 23]));
        assert_eq!(parse_ports("-3"), Ok(vec![1, 2, 3]));
        assert_eq!(parse_ports("65534-"), Ok(vec![65534, 65535]));
        assert_eq!(parse_ports("-").map(|p| p.len()), Ok(65535));
        assert_eq!(parse_ports("80,20-22,21"), Ok(vec![20, 21, 22, 80])); // chevauchement
    }

    #[test]
    fn entrees_invalides() {
        let invalides = [
            "", "abc", "70000", "0", "80-22", "22,,80", "22,", "1-2-3", "0-10",
        ];
        for spec in invalides {
            assert!(
                parse_ports(spec).is_err(),
                "« {spec} » aurait dû être refusé"
            );
        }
    }
}