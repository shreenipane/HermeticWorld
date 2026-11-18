#![forbid(unsafe_code)]

//! # Hermetic Trust
//!
//! Deterministic CA minting and rootfs trust injection.
//!
//! # Preconditions
//! The rootfs must not be modified concurrently during install (exclusive access).

pub mod asn1;
pub mod cert;
pub mod error;
pub mod install;
pub mod jks;

pub use cert::{
    atomic_write_file, check_not_alias, compute_ca_validity, compute_leaf_validity,
    compute_serial_number, derive_ca_seed, generate_rsa_key_from_seed, mint_ca, mint_leaf,
    read_cert_file_bounded, read_seed_file, restore_ca, validate_dns_name, validate_output_path,
    write_private_key_file, Ca, LeafCert, MAX_HOSTNAME_BYTES, MAX_LEAF_HOSTNAMES,
};
pub use error::TrustError;
pub use install::{
    append_pem_bundle_in_root, atomic_write_in_root, atomic_write_preserving_handle,
    bundle_contains_cert, check_report_target_collision, encode_path_lossless, install_ca,
    install_ca_with_options, open_child_dir, open_dir_handle, open_parent_dir_handle,
    read_file_capped_from_parent, record_ownership_guard, resolve_in_rootfs, safe_join_rootfs,
    safe_join_rootfs_from, set_before_dir_enum_hook_guard, set_before_mutation_hook_guard,
    set_before_use_hook_guard, set_chown_failure_guard, BeforeDirEnumHookGuard,
    BeforeMutationHookGuard, BeforeUseHookGuard, ChownFailureGuard, GuestOwner, InstallOptions,
    InstallReport, OwnershipRecord, OwnershipRecordGuard, OwnershipTarget, Resolution, SkippedPath,
    MAX_AGGREGATE_BYTES, MAX_CA_CERT_INPUT_BYTES, MAX_JKS_BYTES, MAX_PEM_BUNDLE_BYTES,
    MAX_REPORT_ENTRIES, MAX_TREE_DEPTH, MAX_TREE_ENTRIES, NEW_DIR_MODE, NEW_FILE_MODE,
};
pub use jks::{
    compute_jks_integrity_hash, create_empty_jks, inject_ca_into_jks, is_pkcs12, parse_jks,
    JksEntry, JksProcessStatus, JKS_APHRODITE, JKS_DEFAULT_PASSWORD, JKS_MAGIC, JKS_VERSION_2,
};
