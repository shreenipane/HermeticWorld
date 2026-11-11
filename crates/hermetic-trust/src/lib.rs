#![forbid(unsafe_code)]

pub mod asn1;
pub mod cert;
pub mod error;
pub mod install;
pub mod jks;

pub use cert::{
    compute_ca_validity, compute_leaf_validity, compute_serial_number, derive_ca_seed,
    generate_rsa_key_from_seed, mint_ca, mint_leaf, read_seed_file, write_private_key_file, Ca,
    LeafCert,
};
pub use error::TrustError;
pub use install::{
    append_pem_bundle_idempotent, atomic_write_preserving, bundle_contains_cert, install_ca,
    resolve_in_rootfs, safe_join_rootfs, safe_join_rootfs_from, InstallReport, SkippedPath,
};
pub use jks::{
    compute_jks_integrity_hash, create_empty_jks, inject_ca_into_jks, is_pkcs12, parse_jks,
    JksEntry, JksProcessStatus, JKS_APHRODITE, JKS_DEFAULT_PASSWORD, JKS_MAGIC, JKS_VERSION_2,
};
