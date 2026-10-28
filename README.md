# scanner — Scanner de ports TCP en Rust

Un petit scanner de ports TCP, écrit à la main en Rust pour comprendre comment fonctionne un outil comme nmap.

Il essaie de se connecter à chaque port d'une machine et dit lesquels sont **ouverts**.

> ⚠️ **À utiliser uniquement sur vos propres machines** ou sur un réseau où vous avez une autorisation explicite.
> Ce projet fait partie d'un labo de cybersécurité personnel et isolé.

---

## Ce que fait l'outil

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
| `-t`, `--target` | Adresse IP à scanner (IPv4 ou IPv6) | `127.0.0.1` | `-t 192.168.50.10` |
| `-p`, `--ports` | Ports à scanner | `1-1024` | `-p 22,80,443` |
| `-c`, `--concurrency` | Nombre de connexions en même temps | `500` | `-c 100` |
| `--timeout-ms` | Temps d'attente max par port (millisecondes) | `1500` | `--timeout-ms 500` |
| `-h`, `--help` | Affiche l'aide | — | `--help` |

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

# Scanner plus vite une machine protégée par un pare-feu
./target/release/scanner -t 192.168.50.10 -p- --timeout-ms 300
```

---

## Lire le résultat

Exemple réel, avec un serveur web sur le port 8080 :

```
$ ./target/release/scanner -p 20-25,8080
Scan de 127.0.0.1 : 7 port(s) à tester
Port 8080 : OUVERT
1 ouvert(s), 6 fermé(s), 0 filtré(s), 0 erreur(s)
```

Seuls les ports **ouverts** sont listés un par un. Les autres sont comptés dans la dernière ligne.

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
├── main.rs    lit les options, lance le scan, affiche le résultat
├── lib.rs     la bibliothèque : déclare les modules ci-dessous
├── ports.rs   lit la liste de ports écrite par l'utilisateur (-p)
└── scan.rs    fait le scan : connexions en parallèle, timeout, état des ports
```

Toute la logique est dans la bibliothèque (`lib.rs`, `ports.rs`, `scan.rs`). Elle pourra être réutilisée par les autres outils du labo.

---

## Tests et qualité du code

```bash
cargo test                      # lance les tests
cargo fmt --check               # vérifie la mise en forme du code
cargo clippy --all-targets      # cherche les erreurs courantes
```

Les tests vérifient notamment :
- la détection d'un port ouvert et d'un port fermé ;
- la lecture de toutes les formes de `-p`, et le refus des entrées invalides (`80-22`, `70000`, `abc`…) ;
- que le scan complet renvoie bien un résultat trié par port.

---

## Limites connues

- **TCP uniquement** : pas de scan UDP.
- **Une adresse IP** comme cible : les noms de domaine (`exemple.com`) ne sont pas acceptés.
- Le scan est un « TCP connect » : il ouvre une vraie connexion complète, qui est donc visible par la machine scannée (elle peut apparaître dans ses journaux).
- Pas de détection du service ou de sa version (l'outil dit qu'un port est ouvert, pas ce qui tourne dessus).
- Par rapport à nmap : pas de noms de services dans `-p` (`-p ssh`), pas de port 0, et les tests sont lancés dans l'ordre croissant au lieu d'un ordre aléatoire.

---

## Références

- [Nmap — Port Specification and Scan Order](https://nmap.org/book/man-port-specification.html) : la syntaxe de `-p` reprise ici.
- [Nmap — Port Scanning Basics](https://nmap.org/book/man-port-scanning-basics.html) : la définition des états ouvert, fermé et filtré.
- [Tutoriel Tokio](https://tokio.rs/tokio/tutorial) : la programmation asynchrone en Rust.
- [The Rust Programming Language](https://doc.rust-lang.org/book/) : le livre officiel de Rust.