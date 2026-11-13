#![forbid(unsafe_code)]

pub mod respond;
mod safe_io;
pub mod table;
pub mod wire;

pub use respond::respond;
pub use table::{
    DnsTable, TableError, MAX_A_RECORDS_PER_NAME, MAX_DNS_LABELS, MAX_DNS_LABEL_LEN,
    MAX_DNS_NAME_LEN, MAX_TABLE_JSON_BYTES, MAX_TABLE_RECORDS, MIN_DNS_LABEL_LEN,
};
pub use wire::{
    DnsHeader, DnsQuery, DnsQuestion, DnsResponse, Rcode, ResourceRecordA, WireError,
    DEFAULT_TTL_SECONDS, DNS_HEADER_LEN, MAX_RESPONSE_ANSWERS, MAX_UDP_PAYLOAD_BYTES,
    MAX_WIRE_NAME_LEN, QCLASS_IN, QTYPE_A, QTYPE_AAAA,
};
