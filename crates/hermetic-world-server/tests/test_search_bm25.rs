#![forbid(unsafe_code)]

mod support;

use std::collections::HashMap;
use std::fs;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::thread;
use std::time::Duration;
use support::{create_private_dir_all, private_tempdir};
use time::macros::datetime;

use hermetic_common::{Method, RequestFrame, ResponseFrame};
use hermetic_world_server::search::{
    build_month_index, build_ram_index, DocumentRecord, ReplayCapture, ReplayIndex,
    ReplayIndexDocument, SearchEngine, SearchError, SearchRecipe, SearchResponse, MAX_QUERY_BYTES,
    SCHEMA_REPLAY_INDEX_V1, SCHEMA_SEARCH_RECIPE_V1,
};
use hermetic_world_server::{ServerConfig, ServerExit, WorldServer};

const MONTH: &str = "2023-04";
const FIRST_DAY_CUTOFF: &str = "2023-04-01T00:00:00Z";

fn sha256_hex(data: &[u8]) -> String {
    hermetic_common::hash::sha256_hex(data)
}

fn sample_doc(
    body: &[u8],
    url: &str,
    title: &str,
    captured: &str,
    source: &str,
) -> (DocumentRecord, (String, Vec<u8>)) {
    let digest = sha256_hex(body);
    let record = DocumentRecord {
        url: url.to_string(),
        title: title.to_string(),
        captured: captured.to_string(),
        source: source.to_string(),
        record_sha256: "a".repeat(64),
        text_sha256: digest.clone(),
    };
    (record, (digest, body.to_vec()))
}

fn fixture_corpus() -> (SearchRecipe, HashMap<String, Vec<u8>>) {
    let (d1, b1) = sample_doc(
        b"Python HTTP library for humans requests is great",
        "https://example.org/requests",
        "Python Requests Guide",
        "2023-03-31T23:59:59.999999999Z",
        "wayback",
    );
    let (d2, b2) = sample_doc(
        b"Python urllib and urllib3 library documentation for network requests",
        "https://example.org/urllib",
        "Urllib Overview",
        "2023-03-15T12:00:00Z",
        "common-crawl",
    );
    let (d3, b3) = sample_doc(
        b"Rust programming language cargo and crates",
        "https://example.org/rust",
        "The Rust Book",
        "2023-02-01T00:00:00Z",
        "software-heritage",
    );
    // At boundary -> strictly excluded
    let (d4, b4) = sample_doc(
        b"Future post April 1st secret leak",
        "https://example.org/future-april1",
        "April 1 Announcement",
        "2023-04-01T00:00:00Z",
        "wayback",
    );
    // Way in future -> strictly excluded
    let (d5, b5) = sample_doc(
        b"Future secret 2024 confidential benchmark leak",
        "https://example.org/future-2024",
        "Future 2024",
        "2024-01-01T00:00:00Z",
        "common-crawl",
    );

    let recipe = SearchRecipe {
        schema: SCHEMA_SEARCH_RECIPE_V1.to_string(),
        month: MONTH.to_string(),
        documents: vec![d1, d2, d3, d4, d5],
    };

    let mut blobs = HashMap::new();
    blobs.insert(b1.0, b1.1);
    blobs.insert(b2.0, b2.1);
    blobs.insert(b3.0, b3.1);
    blobs.insert(b4.0, b4.1);
    blobs.insert(b5.0, b5.1);

    (recipe, blobs)
}

#[test]
fn test_search_known_answer_and_bm25_ranking() {
    let (recipe, blobs) = fixture_corpus();
    let raw_recipe = serde_json::to_vec(&recipe).unwrap();

    let (index, schema, meta) = build_ram_index(&raw_recipe, &blobs, Some(MONTH)).unwrap();
    assert_eq!(meta.document_count, 3);
    assert_eq!(meta.month, MONTH);
    assert_eq!(meta.first_day_cutoff, FIRST_DAY_CUTOFF);

    let engine = SearchEngine::from_ram(index, schema, meta).unwrap();

    // Query 1: "requests" -> should match requests (in title + body) and urllib (in body)
    let resp = engine.query("requests", Some(10)).unwrap();
    assert_eq!(resp.total_hits, 2);
    // Requests has "requests" in title and body, higher BM25 score
    assert_eq!(resp.results[0].url, "https://example.org/requests");
    assert_eq!(resp.results[1].url, "https://example.org/urllib");
    assert!(resp.results[0].score > resp.results[1].score);

    // Query 2: "Rust" -> should match only rust
    let resp_rust = engine.query("Rust", None).unwrap();
    assert_eq!(resp_rust.total_hits, 1);
    assert_eq!(resp_rust.results[0].url, "https://example.org/rust");
    assert_eq!(resp_rust.results[0].title, "The Rust Book");

    // Query 3: Multi-term query "Python library" -> matches requests and urllib
    let resp_multi = engine.query("Python library", None).unwrap();
    assert_eq!(resp_multi.total_hits, 2);

    // Query 4: Words that only appear in post-cutoff documents must NEVER match
    for future_word in &["secret", "leak", "confidential", "2024", "April"] {
        let resp_future = engine.query(future_word, None).unwrap();
        assert_eq!(
            resp_future.total_hits, 0,
            "future word '{}' must not match",
            future_word
        );
        assert!(resp_future.results.is_empty());
        assert!(resp_future.hits.is_empty());
    }
}

#[test]
fn test_search_determinism_across_builds() {
    let (recipe, blobs) = fixture_corpus();
    let raw_recipe = serde_json::to_vec(&recipe).unwrap();

    let temp1 = private_tempdir().unwrap();
    let temp2 = private_tempdir().unwrap();
    let out1 = temp1.path().join("index1");
    let out2 = temp2.path().join("index2");

    let report1 = build_month_index(&raw_recipe, &blobs, &out1, Some(MONTH)).unwrap();
    let report2 = build_month_index(&raw_recipe, &blobs, &out2, Some(MONTH)).unwrap();

    assert_eq!(report1.documents_indexed, report2.documents_indexed);
    assert_eq!(report1.month, report2.month);

    let engine1 = SearchEngine::open(&out1, Some(MONTH), None).unwrap();
    let engine2 = SearchEngine::open(&out2, Some(MONTH), None).unwrap();

    let queries = ["python", "requests", "rust", "library", "nonexistent"];
    for q in queries {
        let r1 = engine1.query(q, Some(10)).unwrap();
        let r2 = engine2.query(q, Some(10)).unwrap();
        assert_eq!(r1, r2, "query '{}' must return identical results", q);
    }
}

#[test]
fn test_search_month_cutoff_strictly_excludes_future_documents() {
    let (d_ok, b_ok) = sample_doc(
        b"Valid document March 31st",
        "https://example.org/valid",
        "Valid",
        "2023-03-31T23:59:59.999999999Z",
        "wayback",
    );
    let (d_boundary, b_boundary) = sample_doc(
        b"Boundary document April 1st midnight exactly",
        "https://example.org/boundary",
        "Boundary",
        "2023-04-01T00:00:00Z",
        "wayback",
    );
    let (d_nano, b_nano) = sample_doc(
        b"One nanosecond after midnight",
        "https://example.org/nano",
        "Nano",
        "2023-04-01T00:00:00.000000001Z",
        "wayback",
    );

    let mut blobs = HashMap::new();
    blobs.insert(b_ok.0, b_ok.1);
    blobs.insert(b_boundary.0, b_boundary.1);
    blobs.insert(b_nano.0, b_nano.1);

    let recipe = SearchRecipe {
        schema: SCHEMA_SEARCH_RECIPE_V1.to_string(),
        month: "2023-04".to_string(),
        documents: vec![d_ok, d_boundary, d_nano],
    };
    let raw = serde_json::to_vec(&recipe).unwrap();

    let (index, schema, meta) = build_ram_index(&raw, &blobs, Some("2023-04")).unwrap();
    assert_eq!(
        meta.document_count, 1,
        "only the pre-April document should be indexed"
    );

    let engine = SearchEngine::from_ram(index, schema, meta).unwrap();
    assert_eq!(engine.query("Valid", None).unwrap().total_hits, 1);
    assert_eq!(engine.query("Boundary", None).unwrap().total_hits, 0);
    assert_eq!(engine.query("nanosecond", None).unwrap().total_hits, 0);
}

#[test]
fn test_search_latest_capture_per_url_selection() {
    let (d_old, b_old) = sample_doc(
        b"Version 1 outdated content",
        "https://example.org/page",
        "Page V1",
        "2023-01-01T00:00:00Z",
        "wayback",
    );
    let (d_new, b_new) = sample_doc(
        b"Version 2 latest March content",
        "https://example.org/page",
        "Page V2",
        "2023-03-25T00:00:00Z",
        "wayback",
    );
    let (d_future, b_future) = sample_doc(
        b"Version 3 future April content",
        "https://example.org/page",
        "Page V3",
        "2023-04-02T00:00:00Z",
        "wayback",
    );

    let mut blobs = HashMap::new();
    blobs.insert(b_old.0, b_old.1);
    blobs.insert(b_new.0, b_new.1);
    blobs.insert(b_future.0, b_future.1);

    let recipe = SearchRecipe {
        schema: SCHEMA_SEARCH_RECIPE_V1.to_string(),
        month: "2023-04".to_string(),
        documents: vec![d_old, d_new, d_future],
    };
    let raw = serde_json::to_vec(&recipe).unwrap();

    let (index, schema, meta) = build_ram_index(&raw, &blobs, Some("2023-04")).unwrap();
    assert_eq!(meta.document_count, 1);

    let engine = SearchEngine::from_ram(index, schema, meta).unwrap();
    // V2 is indexed
    assert_eq!(engine.query("latest", None).unwrap().total_hits, 1);
    assert_eq!(
        engine.query("latest", None).unwrap().results[0].title,
        "Page V2"
    );
    // V1 was superseded
    assert_eq!(engine.query("outdated", None).unwrap().total_hits, 0);
    // V3 was post-cutoff
    assert_eq!(engine.query("future", None).unwrap().total_hits, 0);
}

#[test]
fn test_search_empty_index_known_answer() {
    let recipe = SearchRecipe {
        schema: SCHEMA_SEARCH_RECIPE_V1.to_string(),
        month: "2023-04".to_string(),
        documents: Vec::new(),
    };
    let raw = serde_json::to_vec(&recipe).unwrap();
    let (index, schema, meta) = build_ram_index(&raw, &HashMap::new(), Some("2023-04")).unwrap();
    assert_eq!(meta.document_count, 0);

    let engine = SearchEngine::from_ram(index, schema, meta).unwrap();
    let resp = engine.query("anything", None).unwrap();
    assert_eq!(resp.total_hits, 0);
    assert!(resp.results.is_empty());
}

#[test]
fn test_search_hostile_queries_never_panic() {
    let (recipe, blobs) = fixture_corpus();
    let raw_recipe = serde_json::to_vec(&recipe).unwrap();
    let (index, schema, meta) = build_ram_index(&raw_recipe, &blobs, Some(MONTH)).unwrap();
    let engine = SearchEngine::from_ram(index, schema, meta).unwrap();

    // 1. Oversized query > 1024 bytes -> Err(QueryCapExceeded)
    let huge_query = "a".repeat(MAX_QUERY_BYTES + 1);
    assert!(matches!(
        engine.query(&huge_query, None),
        Err(SearchError::QueryCapExceeded)
    ));

    // 2. Query with > 32 terms -> Err(QueryCapExceeded)
    let many_terms = (0..35)
        .map(|i| format!("term{i}"))
        .collect::<Vec<_>>()
        .join(" ");
    assert!(matches!(
        engine.query(&many_terms, None),
        Err(SearchError::QueryCapExceeded)
    ));

    // 3. Tantivy syntax bombs and hostile punctuation
    let syntax_bombs = [
        ":::",
        "(((((((",
        "))))))",
        "AND OR NOT",
        "title:\"unclosed quote",
        "body:\\\\\\",
        "~1000000000",
        "^99999999",
        "[* TO *]",
        "{{}}",
        "??**++",
        "   ",
        "",
        "&q=attack&limit=-1",
    ];
    for bomb in syntax_bombs {
        let res = engine.query(bomb, None);
        assert!(res.is_ok(), "bomb '{}' must not panic or error", bomb);
    }
}

#[test]
fn test_search_hostile_recipes_fail_closed() {
    let (d1, b1) = sample_doc(
        b"text",
        "https://example.org/a",
        "Title",
        "2023-03-01T00:00:00Z",
        "wayback",
    );
    let mut blobs = HashMap::new();
    blobs.insert(b1.0.clone(), b1.1.clone());

    // 1. Duplicate (URL, timestamp)
    let dup_recipe = SearchRecipe {
        schema: SCHEMA_SEARCH_RECIPE_V1.to_string(),
        month: "2023-04".to_string(),
        documents: vec![d1.clone(), d1.clone()],
    };
    let res = build_ram_index(
        &serde_json::to_vec(&dup_recipe).unwrap(),
        &blobs,
        Some("2023-04"),
    );
    assert!(matches!(res, Err(SearchError::DuplicateCapture)));

    // 2. Invalid URL
    let invalid_urls = [
        "file:///etc/passwd",
        "https://user:pass@example.org/a",
        "https://example.org:8080/a",
        "https://example.org/../etc/passwd",
        "https://example.org/#fragment",
        "https://example.org/\\backslash",
        "http://nodot/a",
    ];
    for bad_url in invalid_urls {
        let mut bad_doc = d1.clone();
        bad_doc.url = bad_url.to_string();
        let r = SearchRecipe {
            schema: SCHEMA_SEARCH_RECIPE_V1.to_string(),
            month: "2023-04".to_string(),
            documents: vec![bad_doc],
        };
        let res = build_ram_index(&serde_json::to_vec(&r).unwrap(), &blobs, Some("2023-04"));
        assert!(res.is_err(), "invalid url '{}' must be rejected", bad_url);
    }

    // 3. Payload digest mismatch
    let mut bad_blobs = blobs.clone();
    bad_blobs.insert(d1.text_sha256.clone(), b"tampered content".to_vec());
    let r_good = SearchRecipe {
        schema: SCHEMA_SEARCH_RECIPE_V1.to_string(),
        month: "2023-04".to_string(),
        documents: vec![d1.clone()],
    };
    let res = build_ram_index(
        &serde_json::to_vec(&r_good).unwrap(),
        &bad_blobs,
        Some("2023-04"),
    );
    assert!(matches!(res, Err(SearchError::PayloadDigestMismatch)));

    // 4. Invalid month format
    let bad_months = ["2023-13", "2023-00", "23-04", "2023/04", "host-secret"];
    for bm in bad_months {
        let r_month = SearchRecipe {
            schema: SCHEMA_SEARCH_RECIPE_V1.to_string(),
            month: bm.to_string(),
            documents: vec![d1.clone()],
        };
        let res = build_ram_index(&serde_json::to_vec(&r_month).unwrap(), &blobs, Some(bm));
        assert!(res.is_err(), "bad month '{}' must be rejected", bm);
    }
}

fn send_frame(sock: &Path, req: &RequestFrame) -> ResponseFrame {
    let mut stream = UnixStream::connect(sock).expect("connect to world-server socket");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let bytes = req.encode().expect("encode req");
    use std::io::Write;
    stream.write_all(&bytes).expect("write request frame");
    stream.flush().expect("flush request frame");

    ResponseFrame::read_from(&mut stream, 10 * 1024 * 1024).expect("read response frame")
}

#[test]
fn test_search_world_server_integration_over_socket() {
    let temp = private_tempdir().unwrap();
    let store_dir = temp.path().join("store");
    let log_dir = temp.path().join("log");
    let socket_path = temp.path().join("world.sock");
    let index_dir = temp.path().join("search_index");

    create_private_dir_all(&store_dir).unwrap();
    create_private_dir_all(&log_dir).unwrap();

    // Build BM25 search index
    let (recipe, blobs) = fixture_corpus();
    let raw_recipe = serde_json::to_vec(&recipe).unwrap();
    build_month_index(&raw_recipe, &blobs, &index_dir, Some(MONTH)).unwrap();

    let t_clock = datetime!(2023-04-15 12:00:00 UTC);

    let config = ServerConfig {
        store_dir,
        socket_path: socket_path.clone(),
        log_dir: log_dir.clone(),
        t_clock,
        rate_rps: None,
        burst: None,
        max_requests: None,
        max_bytes: None,
        allow_no_landlock: true,
        no_sandbox: true,
        resume_log: false,
        recover: false,
        frame_deadline: None,
        transmission_deadline: None,
        search_index_dir: Some(index_dir),
        replay_index_path: None,
    };

    let server = WorldServer::new(config).expect("create WorldServer with search");
    let socket_clone = socket_path.clone();
    let handle = thread::spawn(move || {
        let _ = server.run();
    });

    // Wait for listener to be ready
    for _ in 0..50 {
        if socket_clone.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }

    // 1. GET /search?q=requests
    let req = RequestFrame {
        method: Method::Get,
        request_id: 101,
        authority: "search.local".into(),
        path_and_query: "/search?q=requests".into(),
        range: None,
    };
    let resp = send_frame(&socket_clone, &req);
    assert_eq!(resp.request_id, 101);
    assert_eq!(resp.status, 200);

    let parsed: SearchResponse = serde_json::from_slice(&resp.body).expect("parse json response");
    assert_eq!(parsed.total_hits, 2);
    assert_eq!(parsed.results[0].url, "https://example.org/requests");

    // Headers check
    let headers_map: HashMap<_, _> = resp
        .headers
        .iter()
        .map(|h| (h.name.as_str(), h.value.as_str()))
        .collect();
    assert_eq!(headers_map.get("content-type"), Some(&"application/json"));
    assert!(headers_map.contains_key("date"));
    assert_eq!(
        headers_map.get("content-length"),
        Some(&resp.body.len().to_string().as_str())
    );

    // 2. HEAD /search?q=requests
    let head_req = RequestFrame {
        method: Method::Head,
        request_id: 102,
        authority: "search.local".into(),
        path_and_query: "/search?q=requests".into(),
        range: None,
    };
    let head_resp = send_frame(&socket_clone, &head_req);
    assert_eq!(head_resp.request_id, 102);
    assert_eq!(head_resp.status, 200);
    assert!(
        head_resp.body.is_empty(),
        "HEAD response body must be empty"
    );

    // 3. Non-search path miss -> 404
    let miss_req = RequestFrame {
        method: Method::Get,
        request_id: 103,
        authority: "example.org".into(),
        path_and_query: "/missing-file".into(),
        range: None,
    };
    let miss_resp = send_frame(&socket_clone, &miss_req);
    assert_eq!(miss_resp.status, 404);

    // Verify audit log has recorded the search requests
    let log_file = log_dir.join("requests.log");
    assert!(log_file.exists());
    let log_content = fs::read_to_string(&log_file).unwrap();
    assert!(log_content.contains("/search?q=requests"));

    drop(handle);
}

#[test]
fn test_search_world_server_replay_integration() {
    let temp = private_tempdir().unwrap();
    let store_dir = temp.path().join("store");
    let log_dir = temp.path().join("log");
    let socket_path = temp.path().join("world.sock");
    let index_dir = temp.path().join("search_index");
    let replay_path = temp.path().join("replay_index.json");
    let blob_dir = temp.path().join("blobs");

    create_private_dir_all(&store_dir).unwrap();
    create_private_dir_all(&log_dir).unwrap();
    create_private_dir_all(&blob_dir).unwrap();

    // 1. Prepare replay archive
    let page_body = b"<!DOCTYPE html><html><body>Python Requests Page</body></html>";
    let page_digest = sha256_hex(page_body);
    fs::write(blob_dir.join(&page_digest), page_body).unwrap();

    let replay_doc = ReplayIndexDocument {
        schema: "hermetic-replay-index/v1".to_string(),
        cutoff: "2023-04-01T00:00:00.000000001Z".to_string(),
        captures: vec![ReplayCapture {
            url: "https://example.org/requests".to_string(),
            captured: "2023-03-31T23:59:59.999999999Z".to_string(),
            source: "wayback".to_string(),
            record_sha256: "a".repeat(64),
            payload_sha256: page_digest.clone(),
            size: page_body.len(),
            status: 200,
            content_type: "text/html; charset=utf-8".to_string(),
            location: None,
        }],
    };
    fs::write(
        &replay_path,
        serde_json::to_vec_pretty(&replay_doc).unwrap(),
    )
    .unwrap();

    // 2. Build search index pointing to the same page
    let mut blobs = HashMap::new();
    blobs.insert(page_digest.clone(), page_body.to_vec());

    let (d1, _) = sample_doc(
        page_body,
        "https://example.org/requests",
        "Python Requests Guide",
        "2023-03-31T23:59:59.999999999Z",
        "wayback",
    );
    let recipe = SearchRecipe {
        schema: SCHEMA_SEARCH_RECIPE_V1.to_string(),
        month: MONTH.to_string(),
        documents: vec![d1],
    };
    build_month_index(
        &serde_json::to_vec(&recipe).unwrap(),
        &blobs,
        &index_dir,
        Some(MONTH),
    )
    .unwrap();

    let t_clock = datetime!(2023-04-15 12:00:00 UTC);

    let config = ServerConfig {
        store_dir,
        socket_path: socket_path.clone(),
        log_dir: log_dir.clone(),
        t_clock,
        rate_rps: None,
        burst: None,
        max_requests: None,
        max_bytes: None,
        allow_no_landlock: true,
        no_sandbox: true,
        resume_log: false,
        recover: false,
        frame_deadline: None,
        transmission_deadline: None,
        search_index_dir: Some(index_dir),
        replay_index_path: Some(replay_path),
    };

    let server = WorldServer::new(config).expect("create WorldServer");
    let socket_clone = socket_path.clone();
    let handle = thread::spawn(move || {
        let _ = server.run();
    });

    for _ in 0..50 {
        if socket_clone.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }

    // Step A: Search for "requests"
    let search_req = RequestFrame {
        method: Method::Get,
        request_id: 1,
        authority: "search.local".into(),
        path_and_query: "/search?q=requests".into(),
        range: None,
    };
    let search_resp = send_frame(&socket_clone, &search_req);
    assert_eq!(search_resp.status, 200);
    let search_data: SearchResponse = serde_json::from_slice(&search_resp.body).unwrap();
    assert_eq!(search_data.total_hits, 1);
    let found_url = &search_data.results[0].url;
    assert_eq!(found_url, "https://example.org/requests");

    // Step B: Follow-up GET to fetch the archived page found in search
    let page_req = RequestFrame {
        method: Method::Get,
        request_id: 2,
        authority: "example.org".into(),
        path_and_query: "/requests".into(),
        range: None,
    };
    let page_resp = send_frame(&socket_clone, &page_req);
    assert_eq!(page_resp.status, 200);
    assert_eq!(page_resp.body, page_body);

    let headers_map: HashMap<_, _> = page_resp
        .headers
        .iter()
        .map(|h| (h.name.as_str(), h.value.as_str()))
        .collect();
    assert_eq!(
        headers_map.get("content-type"),
        Some(&"text/html; charset=utf-8")
    );
    assert!(headers_map.contains_key("date"));
    // Ensure pywb and memento headers are not present
    assert!(!headers_map.contains_key("server"));
    assert!(!headers_map.contains_key("memento-datetime"));
    assert!(!headers_map.contains_key("x-archive-orig-date"));

    drop(handle);
}

#[test]
fn test_search_post_cutoff_index_refused_at_startup() {
    let temp = private_tempdir().unwrap();
    let store_dir = temp.path().join("store");
    let log_dir = temp.path().join("log");
    let socket_path = temp.path().join("world.sock");
    let index_dir = temp.path().join("search_index");

    create_private_dir_all(&store_dir).unwrap();
    create_private_dir_all(&log_dir).unwrap();

    // Build index for month 2023-04 (first day cutoff: 2023-04-01)
    let (recipe, blobs) = fixture_corpus();
    let raw_recipe = serde_json::to_vec(&recipe).unwrap();
    build_month_index(&raw_recipe, &blobs, &index_dir, Some("2023-04")).unwrap();

    // t_clock is in March 2023, BEFORE the index's April cutoff!
    let t_clock_past = datetime!(2023-03-15 12:00:00 UTC);

    let config = ServerConfig {
        store_dir,
        socket_path,
        log_dir,
        t_clock: t_clock_past,
        rate_rps: None,
        burst: None,
        max_requests: None,
        max_bytes: None,
        allow_no_landlock: true,
        no_sandbox: true,
        resume_log: false,
        recover: false,
        frame_deadline: None,
        transmission_deadline: None,
        search_index_dir: Some(index_dir),
        replay_index_path: None,
    };

    // Must fail closed with StartupFailed
    let server_res = WorldServer::new(config);
    assert!(
        matches!(server_res, Err(ServerExit::StartupFailed)),
        "post-cutoff search index relative to t_clock must fail closed"
    );
}

#[test]
fn test_search_error_response_json_escaping() {
    // Errors containing quotes and backslashes (such as tantivy error messages quoting field names)
    // must be serialized into valid escaped JSON, not inserted unescaped into format!("{\"error\":\"{}\"}").
    let err =
        SearchError::Tantivy(r#"schema error: field "title" with \escaped\ path"#.to_string());
    let (status, ct, resp_body) = SearchEngine::format_error_response(&err);
    assert_eq!(status, 400);
    assert_eq!(ct, Some("application/json".to_string()));

    // Verify response body parses as valid JSON with serde_json
    let parsed: serde_json::Value =
        serde_json::from_slice(&resp_body).expect("error body must be valid json");
    let err_msg = parsed["error"].as_str().expect("error must be a string");
    assert!(
        err_msg.contains(r#"field "title""#),
        "error message should contain unescaped content in string: {err_msg}"
    );

    // Also test PolicyMismatch with quotes
    let policy_err =
        SearchError::PolicyMismatch(r#"invalid policy for "requests" archive"#.to_string());
    let (status2, ct2, resp_body2) = SearchEngine::format_error_response(&policy_err);
    assert_eq!(status2, 400);
    assert_eq!(ct2, Some("application/json".to_string()));
    let parsed2: serde_json::Value =
        serde_json::from_slice(&resp_body2).expect("policy error body must be valid json");
    assert_eq!(
        parsed2["error"].as_str().unwrap(),
        r#"invalid search index policy or cutoff mismatch: invalid policy for "requests" archive"#
    );
}

#[test]
fn test_search_path_on_non_search_authority_serves_replay_not_search_engine() {
    let temp = private_tempdir().unwrap();
    let store_dir = temp.path().join("store");
    let log_dir = temp.path().join("log");
    let socket_path = temp.path().join("world.sock");
    let index_dir = temp.path().join("search_index");

    create_private_dir_all(&store_dir).unwrap();
    create_private_dir_all(&log_dir).unwrap();

    let (recipe, blobs) = fixture_corpus();
    let raw_recipe = serde_json::to_vec(&recipe).unwrap();
    build_month_index(&raw_recipe, &blobs, &index_dir, Some(MONTH)).unwrap();

    let replay_path = store_dir.join("replay_index.json");
    let blob_dir = store_dir.join("blobs");
    create_private_dir_all(&blob_dir).unwrap();

    let page_body = b"archived github search response";
    let page_hash = sha256_hex(page_body);
    fs::write(blob_dir.join(&page_hash), page_body).unwrap();

    let replay_doc = ReplayIndexDocument {
        schema: SCHEMA_REPLAY_INDEX_V1.to_string(),
        cutoff: "2023-04-01T00:00:00Z".to_string(),
        captures: vec![ReplayCapture {
            url: "https://github.com/search?q=requests".to_string(),
            captured: "2023-03-25T10:00:00Z".to_string(),
            source: "wayback".to_string(),
            record_sha256: "b".repeat(64),
            payload_sha256: page_hash,
            size: page_body.len(),
            status: 200,
            content_type: "text/html; charset=utf-8".to_string(),
            location: None,
        }],
    };
    fs::write(&replay_path, serde_json::to_vec(&replay_doc).unwrap()).unwrap();

    let t_clock = datetime!(2023-04-15 12:00:00 UTC);

    let config = ServerConfig {
        store_dir,
        socket_path: socket_path.clone(),
        log_dir,
        t_clock,
        rate_rps: None,
        burst: None,
        max_requests: None,
        max_bytes: None,
        allow_no_landlock: true,
        no_sandbox: true,
        resume_log: false,
        recover: false,
        frame_deadline: None,
        transmission_deadline: None,
        search_index_dir: Some(index_dir),
        replay_index_path: Some(replay_path),
    };

    let server = WorldServer::new(config).expect("create WorldServer");
    let socket_clone = socket_path.clone();
    let handle = thread::spawn(move || {
        let _ = server.run();
    });

    for _ in 0..50 {
        if socket_clone.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }

    // Request to non-search authority github.com on path /search?q=requests
    let req = RequestFrame {
        method: Method::Get,
        request_id: 1,
        authority: "github.com".into(),
        path_and_query: "/search?q=requests".into(),
        range: None,
    };
    let resp = send_frame(&socket_clone, &req);
    assert_eq!(resp.status, 200);
    // Must be the archived replay response, NOT search engine JSON results
    assert_eq!(resp.body, page_body);

    // Also verify non-search authority miss (/api/search on ordinary site) returns 404
    let miss_req = RequestFrame {
        method: Method::Get,
        request_id: 2,
        authority: "example.org".into(),
        path_and_query: "/api/search".into(),
        range: None,
    };
    let miss_resp = send_frame(&socket_clone, &miss_req);
    assert_eq!(miss_resp.status, 404);

    drop(handle);
}

#[test]
fn test_replay_index_rejects_payload_digest_mismatch() {
    let original = b"original content";
    let tampered = b"tampered content"; // same length: 16 bytes
    assert_eq!(original.len(), tampered.len());
    let orig_hash = sha256_hex(original);

    let doc = ReplayIndexDocument {
        schema: SCHEMA_REPLAY_INDEX_V1.to_string(),
        cutoff: "2023-04-01T00:00:00Z".to_string(),
        captures: vec![ReplayCapture {
            url: "https://example.org/test".to_string(),
            captured: "2023-03-15T00:00:00Z".to_string(),
            source: "wayback".to_string(),
            record_sha256: "c".repeat(64),
            payload_sha256: orig_hash.clone(),
            size: original.len(),
            status: 200,
            content_type: "text/plain".to_string(),
            location: None,
        }],
    };
    let index_json = serde_json::to_vec(&doc).unwrap();

    let mut blobs = HashMap::new();
    blobs.insert(orig_hash, tampered.to_vec());

    let res = ReplayIndex::new(&index_json, &blobs, None);
    assert!(
        matches!(res, Err(SearchError::PayloadDigestMismatch)),
        "replay index must reject blob with mismatched payload digest"
    );
}

#[test]
fn test_resume_log_rejects_altered_replay_or_search_binding() {
    let temp = private_tempdir().unwrap();
    let store_dir = temp.path().join("store");
    let log_dir = temp.path().join("log");
    let socket_path = temp.path().join("world.sock");
    create_private_dir_all(&store_dir).unwrap();
    create_private_dir_all(&log_dir).unwrap();

    let blob_dir = store_dir.join("blobs");
    create_private_dir_all(&blob_dir).unwrap();
    let body1 = b"replay one";
    let hash1 = sha256_hex(body1);
    fs::write(blob_dir.join(&hash1), body1).unwrap();

    let body2 = b"replay two";
    let hash2 = sha256_hex(body2);
    fs::write(blob_dir.join(&hash2), body2).unwrap();

    let replay1 = store_dir.join("replay1.json");
    let replay2 = store_dir.join("replay2.json");

    let doc1 = ReplayIndexDocument {
        schema: SCHEMA_REPLAY_INDEX_V1.to_string(),
        cutoff: "2023-04-01T00:00:00Z".to_string(),
        captures: vec![ReplayCapture {
            url: "https://example.org/item".to_string(),
            captured: "2023-03-01T00:00:00Z".to_string(),
            source: "wayback".to_string(),
            record_sha256: "d".repeat(64),
            payload_sha256: hash1,
            size: body1.len(),
            status: 200,
            content_type: "text/plain".to_string(),
            location: None,
        }],
    };
    fs::write(&replay1, serde_json::to_vec(&doc1).unwrap()).unwrap();

    let doc2 = ReplayIndexDocument {
        schema: SCHEMA_REPLAY_INDEX_V1.to_string(),
        cutoff: "2023-04-01T00:00:00Z".to_string(),
        captures: vec![ReplayCapture {
            url: "https://example.org/item".to_string(),
            captured: "2023-03-02T00:00:00Z".to_string(),
            source: "wayback".to_string(),
            record_sha256: "e".repeat(64),
            payload_sha256: hash2,
            size: body2.len(),
            status: 200,
            content_type: "text/plain".to_string(),
            location: None,
        }],
    };
    fs::write(&replay2, serde_json::to_vec(&doc2).unwrap()).unwrap();

    let t_clock = datetime!(2023-04-15 12:00:00 UTC);

    let make_cfg = |replay_opt: Option<std::path::PathBuf>, resume: bool| ServerConfig {
        store_dir: store_dir.clone(),
        socket_path: socket_path.clone(),
        log_dir: log_dir.clone(),
        t_clock,
        rate_rps: None,
        burst: None,
        max_requests: None,
        max_bytes: None,
        allow_no_landlock: true,
        no_sandbox: true,
        resume_log: resume,
        recover: resume,
        frame_deadline: None,
        transmission_deadline: None,
        search_index_dir: None,
        replay_index_path: replay_opt,
    };

    // Run initial server to write run_config binding to log
    let init_server =
        WorldServer::new(make_cfg(Some(replay1.clone()), false)).expect("init server");
    init_server.finish().unwrap();

    // Resuming with the same configuration must succeed
    let server_same =
        WorldServer::new(make_cfg(Some(replay1), true)).expect("resume same must succeed");
    server_same.finish().unwrap();

    // Resuming with a different replay index must fail with StartupFailed
    let server_diff = WorldServer::new(make_cfg(Some(replay2), true));
    assert!(
        matches!(server_diff, Err(ServerExit::StartupFailed)),
        "resuming with altered replay configuration must fail closed"
    );
}

#[test]
fn test_index_sha256_differs_for_different_contents_with_same_count() {
    let (d1, b1) = sample_doc(
        b"Content of first document",
        "https://example.org/first",
        "Title 1",
        "2023-03-01T00:00:00Z",
        "wayback",
    );
    let recipe1 = SearchRecipe {
        schema: SCHEMA_SEARCH_RECIPE_V1.to_string(),
        month: MONTH.to_string(),
        documents: vec![d1],
    };
    let mut blobs1 = HashMap::new();
    blobs1.insert(b1.0, b1.1);
    let (_, _, meta1) =
        build_ram_index(&serde_json::to_vec(&recipe1).unwrap(), &blobs1, Some(MONTH)).unwrap();

    let (d2, b2) = sample_doc(
        b"Content of second different document",
        "https://example.org/second",
        "Title 2",
        "2023-03-01T00:00:00Z",
        "wayback",
    );
    let recipe2 = SearchRecipe {
        schema: SCHEMA_SEARCH_RECIPE_V1.to_string(),
        month: MONTH.to_string(),
        documents: vec![d2],
    };
    let mut blobs2 = HashMap::new();
    blobs2.insert(b2.0, b2.1);
    let (_, _, meta2) =
        build_ram_index(&serde_json::to_vec(&recipe2).unwrap(), &blobs2, Some(MONTH)).unwrap();

    assert_eq!(meta1.document_count, 1);
    assert_eq!(meta2.document_count, 1);
    assert_eq!(meta1.month, meta2.month);
    // Digests must not be equal merely because document count and month are equal
    assert_ne!(
        meta1.index_sha256, meta2.index_sha256,
        "index_sha256 must reflect content integrity"
    );
}

#[test]
fn test_replay_index_serves_newer_capture_regardless_of_order() {
    let body_newer = b"newer content 2023-03-20";
    let body_older = b"older content 2023-03-10";
    let hash_newer = sha256_hex(body_newer);
    let hash_older = sha256_hex(body_older);

    // List newer first, older second
    let doc = ReplayIndexDocument {
        schema: SCHEMA_REPLAY_INDEX_V1.to_string(),
        cutoff: "2023-04-01T00:00:00Z".to_string(),
        captures: vec![
            ReplayCapture {
                url: "https://example.org/page".to_string(),
                captured: "2023-03-20T00:00:00Z".to_string(),
                source: "wayback".to_string(),
                record_sha256: "1".repeat(64),
                payload_sha256: hash_newer.clone(),
                size: body_newer.len(),
                status: 200,
                content_type: "text/plain".to_string(),
                location: None,
            },
            ReplayCapture {
                url: "https://example.org/page".to_string(),
                captured: "2023-03-10T00:00:00Z".to_string(),
                source: "wayback".to_string(),
                record_sha256: "2".repeat(64),
                payload_sha256: hash_older.clone(),
                size: body_older.len(),
                status: 200,
                content_type: "text/plain".to_string(),
                location: None,
            },
        ],
    };

    let mut blobs = HashMap::new();
    blobs.insert(hash_newer, body_newer.to_vec());
    blobs.insert(hash_older, body_older.to_vec());

    let replay =
        ReplayIndex::new(&serde_json::to_vec(&doc).unwrap(), &blobs, None).expect("load replay");
    let resp = replay
        .lookup("https://example.org/page", "GET")
        .expect("lookup");
    // Must serve newer capture, NOT the one listed last in the file
    assert_eq!(resp.body, body_newer);
}

#[test]
fn test_replay_index_rejects_duplicate_capture_timestamps() {
    let body = b"identical timestamp capture";
    let hash = sha256_hex(body);

    let doc = ReplayIndexDocument {
        schema: SCHEMA_REPLAY_INDEX_V1.to_string(),
        cutoff: "2023-04-01T00:00:00Z".to_string(),
        captures: vec![
            ReplayCapture {
                url: "https://example.org/duplicate".to_string(),
                captured: "2023-03-15T00:00:00Z".to_string(),
                source: "wayback".to_string(),
                record_sha256: "3".repeat(64),
                payload_sha256: hash.clone(),
                size: body.len(),
                status: 200,
                content_type: "text/plain".to_string(),
                location: None,
            },
            ReplayCapture {
                url: "https://example.org/duplicate".to_string(),
                captured: "2023-03-15T00:00:00Z".to_string(),
                source: "common-crawl".to_string(),
                record_sha256: "4".repeat(64),
                payload_sha256: hash.clone(),
                size: body.len(),
                status: 200,
                content_type: "text/plain".to_string(),
                location: None,
            },
        ],
    };

    let mut blobs = HashMap::new();
    blobs.insert(hash, body.to_vec());

    let res = ReplayIndex::new(&serde_json::to_vec(&doc).unwrap(), &blobs, None);
    assert!(
        matches!(res, Err(SearchError::DuplicateCapture)),
        "replay index must reject exact duplicate timestamps with DuplicateCapture"
    );
}

#[test]
fn test_world_server_rejects_replay_index_with_cutoff_later_than_t_clock() {
    let temp = private_tempdir().unwrap();
    let store_dir = temp.path().join("store");
    let log_dir = temp.path().join("log");
    let socket_path = temp.path().join("world.sock");
    create_private_dir_all(&store_dir).unwrap();
    create_private_dir_all(&log_dir).unwrap();

    let blob_dir = store_dir.join("blobs");
    create_private_dir_all(&blob_dir).unwrap();
    let body = b"future capture";
    let hash = sha256_hex(body);
    fs::write(blob_dir.join(&hash), body).unwrap();

    let replay_path = store_dir.join("replay_index.json");
    // Replay index cutoff is May 2023
    let doc = ReplayIndexDocument {
        schema: SCHEMA_REPLAY_INDEX_V1.to_string(),
        cutoff: "2023-05-01T00:00:00Z".to_string(),
        captures: vec![ReplayCapture {
            url: "https://example.org/test".to_string(),
            captured: "2023-04-20T00:00:00Z".to_string(),
            source: "wayback".to_string(),
            record_sha256: "5".repeat(64),
            payload_sha256: hash,
            size: body.len(),
            status: 200,
            content_type: "text/plain".to_string(),
            location: None,
        }],
    };
    fs::write(&replay_path, serde_json::to_vec(&doc).unwrap()).unwrap();

    // t_clock is in April 2023, BEFORE the replay cutoff!
    let t_clock = datetime!(2023-04-15 12:00:00 UTC);

    let config = ServerConfig {
        store_dir,
        socket_path,
        log_dir,
        t_clock,
        rate_rps: None,
        burst: None,
        max_requests: None,
        max_bytes: None,
        allow_no_landlock: true,
        no_sandbox: true,
        resume_log: false,
        recover: false,
        frame_deadline: None,
        transmission_deadline: None,
        search_index_dir: None,
        replay_index_path: Some(replay_path),
    };

    let server_res = WorldServer::new(config);
    assert!(
        matches!(server_res, Err(ServerExit::StartupFailed)),
        "replay index with cutoff later than t_clock must be rejected at startup"
    );
}
