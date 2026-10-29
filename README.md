# scanner — Scanner de ports TCP en Rust

Un petit scanner de ports TCP, écrit à la main en Rust pour comprendre comment fonctionne un outil comme nmap.

Il essaie de se connecter à chaque port d'une ou plusieurs machines et dit lesquels sont **ouverts**.

> ⚠️ **À utiliser uniquement sur vos propres machines** ou sur un réseau où vous avez une autorisation explicite.
> Ce projet fait partie d'un labo de cybersécurité personnel et isolé.

---

## Ce que fait l'outil

- Scanne **une ou plusieurs machines** : une IP, une plage, ou un bloc réseau (CIDR).
- Teste beaucoup de ports **en parallèle** (avec `tokio`), au lieu d'un par un.
- Abandonne un port qui ne répond pas après un **délai** (timeout).
- Accepte les listes de ports **comme nmap** : `22,80,443`, `1-1024`, `-` (tous).
- Classe chaque port : **ouvert**, **fermé**, **filtré** ou **erreur**.
- **Signale** toujours quand un résultat est incomplet, au lieu de le cacher.
- Ne demande **aucun privilège** (pas besoin de `sudo`).

---

## Installation

Il faut Rust, installé avec [rustup](https://rustup.rs).

```bash
git clone https://github.com/MkDriss/scanner
cd scanner
cargo build --release
```

Le programme se trouve ensuite dans `./target/release/scanner`.

---

## Utilisation

```bash
./target/release/scanner [OPTIONS]
```

Sans option, il scanne les ports **1 à 1024** de **127.0.0.1** (votre propre machine).

### Les options

| Option | Rôle | Par défaut | Exemple |
| --- | --- | --- | --- |
| `-t`, `--target` | Machine(s) à scanner | `127.0.0.1` | `-t 192.168.50.0/24` |
| `-p`, `--ports` | Ports à scanner | `1-1024` | `-p 22,80,443` |
| `-c`, `--concurrency` | Nombre de connexions en même temps | `500` | `-c 100` |
| `--timeout-ms` | Temps d'attente max par port (millisecondes) | `1500` | `--timeout-ms 500` |
| `-h`, `--help` | Affiche l'aide | — | `--help` |

### Choisir la ou les machines (`-t`)

| Je veux scanner… | J'écris |
| --- | --- |
| une seule machine | `-t 192.168.50.10` |
| une machine en IPv6 | `-t ::1` |
| une plage d'adresses | `-t 192.168.50.1-50` |
| tout un réseau (bloc CIDR) | `-t 192.168.50.0/24` |
| un mélange | `-t 192.168.50.10,192.168.50.20-30` |

Les plages (`.1-50`) et les blocs CIDR (`/24`) ne fonctionnent qu'en **IPv4**. Une adresse IPv6 doit être donnée seule.

Pour éviter un scan lancé par erreur sur un réseau énorme, un bloc CIDR est limité à **65 536 adresses** (préfixe `/16` ou plus petit en nombre d'adresses, par exemple `/24`, `/16`). Un bloc plus grand comme `/8` est refusé.

### Écrire la liste de ports (`-p`)

| Je veux scanner… | J'écris |
| --- | --- |
| un seul port | `-p 22` |
| plusieurs ports | `-p 22,80,443` |
| une plage | `-p 20-25` |
| du port 1 jusqu'à 100 | `-p -100` |
| du port 60000 jusqu'à la fin (65535) | `-p 60000-` |
| tous les ports | `-p-` |
| un mélange | `-p 22,80-90,8080` |

Les ports en double sont ignorés. Les tests sont lancés dans l'ordre croissant des ports.

### Exemples

```bash
# Scanner les ports 1 à 1024 de ma machine
./target/release/scanner

# Vérifier si un serveur web tourne sur le port 8080
./target/release/scanner -p 8080

# Scanner tous les ports d'une machine du labo
./target/release/scanner -t 192.168.50.10 -p-

# Scanner un réseau entier sur quelques ports courants
./target/release/scanner -t 192.168.50.0/24 -p 22,80,443,8080

# Scanner une plage de machines
./target/release/scanner -t 192.168.50.1-50 -p 22,80

# Scanner plus vite une machine protégée par un pare-feu
./target/release/scanner -t 192.168.50.10 -p- --timeout-ms 300
```

---

## Lire le résultat

Le résultat est groupé par machine. Exemple réel, avec un serveur web sur le port 8080 :

```
$ ./target/release/scanner -p 20-25,8080
Scan de 1 machine(s) sur 7 port(s)

=== 127.0.0.1 ===
Port 8080 : OUVERT
1 ouvert(s), 6 fermé(s), 0 filtré(s), 0 erreur(s)
```

Pour chaque machine, seuls les ports **ouverts** sont listés un par un. Les autres sont comptés dans la ligne de bilan.

Quand on scanne **plusieurs** machines, celles qui n'ont aucun port ouvert ne sont pas affichées, pour garder un résultat lisible.

| État | Ce qui s'est passé | En clair |
| --- | --- | --- |
| **Ouvert** | La connexion a réussi | Un programme écoute sur ce port |
| **Fermé** | La machine a refusé la connexion | La machine répond, mais rien n'écoute sur ce port |
| **Filtré** | Pas de réponse avant le timeout | Sans doute bloqué par un pare-feu |
| **Erreur** | Un autre problème a empêché le test | On ne sait pas : le résultat est incomplet |

### Si le résultat est incomplet

Le scanner affiche un avertissement qui commence par `⚠ Résultats incomplets`. Dans ce cas, **ne vous fiez pas au résultat** : un port ouvert peut faire partie des ports non testés.

La cause la plus fréquente est `Too many open files` : trop de connexions en même temps pour votre système. Relancez avec une valeur de `-c` plus petite, par exemple `-c 100`. La commande `ulimit -n` affiche la limite de votre système.

---

## Structure du code

```
src/
├── main.rs      lit les options, lance le scan, affiche le résultat
├── lib.rs       la bibliothèque : déclare les modules ci-dessous
├── targets.rs   lit la ou les machines à scanner (-t : IP, plage, CIDR)
├── ports.rs     lit la liste de ports écrite par l'utilisateur (-p)
└── scan.rs      fait le scan : connexions en parallèle, timeout, état des ports
```

Toute la logique est dans la bibliothèque (`lib.rs`, `targets.rs`, `ports.rs`, `scan.rs`). Elle pourra être réutilisée par les autres outils du labo.

---

## Tests et qualité du code

```bash
cargo test                      # lance les tests
cargo fmt --check               # vérifie la mise en forme du code
cargo clippy --all-targets      # cherche les erreurs courantes
```

Les tests vérifient notamment :
- la détection d'un port ouvert et d'un port fermé ;
- la lecture de toutes les formes de `-t` (IP, plage, CIDR) et de `-p`, et le refus des entrées invalides (`80-22`, `70000`, `10.0.0.0/8`, `abc`…) ;
- que le scan complet renvoie bien un résultat trié par port.

---

## Limites connues

- **TCP uniquement** : pas de scan UDP.
- **Adresses IP seulement** comme cible : les noms de domaine (`exemple.com`) ne sont pas acceptés.
- Les machines sont scannées **l'une après l'autre** (les ports d'une même machine, eux, sont testés en parallèle). Scanner un grand réseau dont beaucoup d'adresses sont absentes est donc lent : chaque machine absente fait attendre le timeout. La découverte des machines vivantes est prévue pour corriger ce point.
- Le scan est un « TCP connect » : il ouvre une vraie connexion complète, qui est donc visible par la machine scannée (elle peut apparaître dans ses journaux).
- Pas de détection du service ou de sa version (l'outil dit qu'un port est ouvert, pas ce qui tourne dessus).
- Par rapport à nmap : pas de noms de services dans `-p` (`-p ssh`), pas de port 0, et les tests sont lancés dans l'ordre croissant au lieu d'un ordre aléatoire.

---

## Références

- [Nmap — Port Specification and Scan Order](https://nmap.org/book/man-port-specification.html) : la syntaxe de `-p` reprise ici.
- [Nmap — Port Scanning Basics](https://nmap.org/book/man-port-scanning-basics.html) : la définition des états ouvert, fermé et filtré.
- [Tutoriel Tokio](https://tokio.rs/tokio/tutorial) : la programmation asynchrone en Rust.
- [The Rust Programming Language](https://doc.rust-lang.org/book/) : le livre officiel de Rust.