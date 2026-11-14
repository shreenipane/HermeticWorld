use hermetic_gateway::{
    quota::{QuotaTracker, QuotasConfig},
    GuestClock, SanitizingSseReader, StreamSlotGuard, StreamUsage,
};
use std::{
    io::{Cursor, Read},
    sync::{Arc, Mutex},
    time::Duration,
};

#[test]
fn streaming_usage_is_committed_before_response_eof() {
    let quota = Arc::new(QuotaTracker::new(QuotasConfig::default()));
    quota.check_and_acquire(0).unwrap();
    let usage = Arc::new(Mutex::new(StreamUsage::default()));
    let slot = Arc::new(StreamSlotGuard::new(quota.clone(), usage.clone()));
    let clock = GuestClock::frozen(
        time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
        Duration::from_secs(120),
    );
    let payload = b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10,\"output_tokens\":1}}}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":15}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
    let mut reader =
        SanitizingSseReader::with_slot_guard(Cursor::new(payload), clock, usage, slot.clone());
    let mut byte = [0];
    assert_eq!(reader.read(&mut byte).unwrap(), 1);
    assert_eq!(quota.snapshot().concurrent_requests, 1);
    let mut output = Vec::new();
    reader.read_to_end(&mut output).unwrap();
    assert!(String::from_utf8(output).unwrap().contains("message_stop"));
    // Keep both reader and handler's guard alive: client EOF must imply
    // final usage is visible even if the handler has not resumed after respond.
    let snapshot = quota.snapshot();
    assert_eq!(snapshot.input_tokens, 10);
    assert_eq!(snapshot.output_tokens, 15);
    assert_eq!(snapshot.concurrent_requests, 0);
    slot.record_and_release().unwrap();
    drop(reader);
    drop(slot);
    assert_eq!(quota.snapshot().output_tokens, 15);
}

#[test]
fn rejected_stream_usage_is_committed_before_response_eof() {
    let quota = Arc::new(QuotaTracker::new(QuotasConfig::default()));
    quota.check_and_acquire(0).unwrap();
    let usage = Arc::new(Mutex::new(StreamUsage::default()));
    let slot = Arc::new(StreamSlotGuard::new(quota.clone(), usage.clone()));
    let clock = GuestClock::frozen(
        time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
        Duration::from_secs(120),
    );
    let payload = b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10,\"output_tokens\":1}}}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":15}}\n\nevent: message_delta\ndata: not-json\n\n";
    let mut reader =
        SanitizingSseReader::with_slot_guard(Cursor::new(payload), clock, usage, slot.clone());
    let mut output = String::new();
    reader.read_to_string(&mut output).unwrap();
    assert!(output.contains("api_error"));
    let snapshot = quota.snapshot();
    assert_eq!(snapshot.input_tokens, 10);
    assert_eq!(snapshot.output_tokens, 15);
    assert_eq!(snapshot.concurrent_requests, 0);
    slot.record_and_release().unwrap();
    drop(reader);
    drop(slot);
    assert_eq!(quota.snapshot().output_tokens, 15);
}
