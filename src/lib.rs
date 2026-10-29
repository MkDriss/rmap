//! Bibliothèque du scanner de ports TCP.
//!
//! Elle contient toute la logique, réutilisable par d'autres outils :
//! - [`targets`] : lecture des cibles (IP, plage `.1-50`, bloc CIDR `/24`) ;
//! - [`ports`] : lecture d'une liste de ports façon nmap (`22,80`, `1-1024`, `-`…) ;
//! - [`scan`] : scan TCP « connect » concurrent, avec timeout.
//!
//! Le binaire (`main.rs`) ne fait que lire les arguments et afficher les résultats.

pub mod ports;
pub mod scan;
pub mod targets;