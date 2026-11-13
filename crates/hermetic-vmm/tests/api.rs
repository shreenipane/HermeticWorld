use hermetic_vmm::{api::*, deadline, ApiRequest, Error};
use serde_json::json;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};
const TIMEOUT: Duration = Duration::from_millis(120);
fn fake(response: Vec<u8>, stall: bool) -> (hermetic_vmm::Result<Response>, Vec<u8>) {
    fake_request(
        ApiRequest {
            method: "PUT".into(),
            path: "/entropy".into(),
            body: json!({}),
        },
        response,
        stall,
    )
}
fn fake_request(
    req: ApiRequest,
    response: Vec<u8>,
    stall: bool,
) -> (hermetic_vmm::Result<Response>, Vec<u8>) {
    let (client, server) = UnixStream::pair().unwrap();
    let server = std::thread::spawn(move || {
        let mut s = std::fs::File::from(std::os::fd::OwnedFd::from(server));
        let mut request = Vec::new();
        let mut buf = [0; 4096];
        loop {
            let n = s.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            request.extend_from_slice(&buf[..n]);
            if let Some(boundary) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = std::str::from_utf8(&request[..boundary]).unwrap();
                let len = head
                    .lines()
                    .find_map(|l| l.strip_prefix("Content-Length: "))
                    .unwrap()
                    .parse::<usize>()
                    .unwrap();
                if request.len() >= boundary + 4 + len {
                    break;
                }
            }
            assert!(request.len() < MAX_REQUEST_BYTES + MAX_HEADER_BYTES);
        }
        if stall {
            std::thread::sleep(Duration::from_millis(250));
        } else {
            let _ = s.write_all(&response);
        }
        request
    });
    let result = call_stream(client, &req, deadline(TIMEOUT).unwrap());
    (result, server.join().unwrap())
}
#[test]
fn trusted_reboot_boot_source_passes_transport_and_rejects_malformed_initrd() {
    let request = ApiRequest {
        method: "PUT".into(),
        path: "/boot-source".into(),
        body: json!({
            "kernel_image_path":"/kernel", "initrd_path":"/initrd",
            "boot_args":"root=/dev/vda ro clocksource=tsc tsc=reliable hermetic.t=1700000000 hermetic.initramfs=1"
        }),
    };
    let (response, wire) = fake_request(
        request.clone(),
        b"HTTP/1.1 204 No Content\r\n\r\n".to_vec(),
        false,
    );
    assert_eq!(response.unwrap().status, 204);
    let body = wire.split(|b| *b == b'\n').next_back().unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(body).unwrap(),
        request.body
    );
    for value in [
        json!(null),
        json!(7),
        json!(""),
        json!("relative"),
        json!("/../initrd"),
    ] {
        let mut bad = request.clone();
        bad.body["initrd_path"] = value;
        let (result, wire) = fake_request(bad, Vec::new(), false);
        assert!(result.is_err());
        assert!(wire.is_empty());
    }
    let mut bad = request;
    bad.body["unknown"] = json!("secret");
    let (result, wire) = fake_request(bad, Vec::new(), false);
    assert!(result.is_err());
    assert!(wire.is_empty());
}

#[test]
fn every_planned_request_passes_the_strict_transport_schema() {
    #[path = "support/mod.rs"]
    mod support;
    use hermetic_vmm::spec::Role;
    for role in [Role::Agent, Role::Net, Role::Extractor, Role::Grader] {
        let spec = support::spec(role).validate().unwrap();
        for request in hermetic_vmm::api_requests(&spec) {
            let (response, _) =
                fake_request(request, b"HTTP/1.1 204 No Content\r\n\r\n".to_vec(), false);
            assert_eq!(response.unwrap().status, 204);
        }
    }
    for (method, path, body) in [
        ("GET", "/", json!({})),
        ("PUT", "/actions", json!({"action_type":"InstanceStart"})),
        ("PUT", "/actions", json!({"action_type":"SendCtrlAltDel"})),
        ("PATCH", "/vm", json!({"state":"Paused"})),
        ("PATCH", "/vm", json!({"state":"Resumed"})),
        (
            "PATCH",
            "/drives/tests",
            json!({"drive_id":"tests","path_on_host":"/tests"}),
        ),
    ] {
        let request = ApiRequest {
            method: method.into(),
            path: path.into(),
            body,
        };
        assert_eq!(
            fake_request(request, b"HTTP/1.1 204 No Content\r\n\r\n".to_vec(), false)
                .0
                .unwrap()
                .status,
            204
        );
    }
}
#[test]
fn correct_request_and_response_known_answer() {
    let (r, request) = fake(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
        false,
    );
    let response = r.unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"{}");
    assert_eq!(request,b"PUT /entropy HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
    assert_eq!(
        fake(b"HTTP/1.1 204 No Content\r\n\r\n".to_vec(), false)
            .0
            .unwrap()
            .status,
        204
    );
}
#[test]
fn fault_body_is_not_exposed() {
    let secret = b"host-secret-date";
    let (result, _) = fake(
        [
            format!(
                "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\n\r\n",
                secret.len()
            )
            .as_bytes(),
            secret,
        ]
        .concat(),
        false,
    );
    let e = result.unwrap_err();
    assert_eq!(e, Error::Api(400));
    assert!(!e.to_string().contains("secret"));
}
#[test]
fn oversized_truncated_and_early_close_are_refused() {
    for response in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 65537\r\n\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 9999999999999999999999999\r\n\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nxx".to_vec(),
        b"HTTP/1.1 2".to_vec(),
        vec![],
    ] {
        assert!(fake(response, false).0.is_err());
    }
}
#[test]
fn stalled_response_hits_overall_deadline() {
    let start = Instant::now();
    let (r, _) = fake(vec![], true);
    assert!(matches!(r, Err(Error::Deadline(_))));
    assert!(start.elapsed() < Duration::from_secs(2));
}
#[test]
fn malicious_http_grammar_is_bounded_and_strict() {
    let cases = [
        "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 20 OK\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\n\r\n",
        "HTTP/1.1 204 No Content\r\nContent-Length: 1\r\n\r\nx",
        "HTTP/1.1 200 OK\r\nfolded\r\n\r\n",
        "HTTP/1.1 200 OK\nInjected\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\rInjected\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length : 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: +0\r\n\r\n",
    ];
    for response in cases {
        assert!(
            fake(response.as_bytes().to_vec(), false).0.is_err(),
            "{response}"
        );
    }
    let mut oversized = b"HTTP/1.1 200 OK\r\nX: ".to_vec();
    oversized.extend(vec![b'a'; MAX_HEADER_BYTES]);
    assert!(fake(oversized, false).0.is_err());
}
#[test]
fn slow_drip_does_not_reset_call_deadline() {
    let (mut read, write) = UnixStream::pair().unwrap();
    let mut write = std::fs::File::from(std::os::fd::OwnedFd::from(write));
    read.set_nonblocking(true).unwrap();
    let server = std::thread::spawn(move || {
        for b in b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}" {
            if write.write_all(&[*b]).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(8));
        }
    });
    let start = Instant::now();
    assert!(matches!(
        read_response(&mut read, deadline(Duration::from_millis(60)).unwrap()),
        Err(Error::Deadline(_))
    ));
    assert!(start.elapsed() < Duration::from_millis(200));
    drop(read);
    server.join().unwrap();
}
#[test]
fn invalid_request_paths_and_large_requests_fail_before_connect() {
    for (method, path, body) in [
        ("PUT", "/entropy", json!({"unexpected":true})),
        (
            "PUT",
            "/machine-config",
            json!({"vcpu_count":0,"mem_size_mib":128,"smt":false}),
        ),
        ("PUT", "/cpu-config", json!({})),
        (
            "PUT",
            "/boot-source",
            json!({"kernel_image_path":"../host", "boot_args":"ro"}),
        ),
        ("PUT", "/vsock", json!({"guest_cid":2,"uds_path":"/vsock"})),
        ("PUT", "/actions", json!({"action_type":"unknown"})),
        ("PATCH", "/vm", json!({"state":"unknown"})),
        (
            "PUT",
            "/drives/tests",
            json!({"drive_id":"other","path_on_host":"/tests","is_read_only":true,"is_root_device":false}),
        ),
    ] {
        let request = ApiRequest {
            method: method.into(),
            path: path.into(),
            body,
        };
        assert_eq!(
            call("/not-present", &request, deadline(TIMEOUT).unwrap()).unwrap_err(),
            Error::Validation("API request body shape")
        );
    }
    for (method, path) in [
        ("PATCH", "/entropy"),
        ("PUT", "/vm"),
        ("PUT", "/"),
        ("DELETE", "/drives/tests"),
        ("GET", "/machine-config"),
    ] {
        let request = ApiRequest {
            method: method.into(),
            path: path.into(),
            body: json!({}),
        };
        assert!(matches!(
            call("/not-present", &request, deadline(TIMEOUT).unwrap()),
            Err(Error::Validation(_))
        ));
    }
    for path in ["/mmds", "/entropy\r\nInjected: value", "/drives/../host"] {
        let request = ApiRequest {
            method: "PUT".into(),
            path: path.into(),
            body: json!({}),
        };
        assert!(matches!(
            call("/not-present", &request, deadline(TIMEOUT).unwrap()),
            Err(Error::Validation(_))
        ));
    }
    let req = ApiRequest {
        method: "PUT".into(),
        path: "/entropy".into(),
        body: json!({"data":"x".repeat(MAX_REQUEST_BYTES+1)}),
    };
    assert!(matches!(
        call("/not-present", &req, deadline(TIMEOUT).unwrap()),
        Err(Error::Validation(_))
    ));
}

#[test]
#[ignore = "requires permission to bind a Unix-domain socket; socketpair robustness tests run in the sandbox"]
fn pathname_client_connects_to_fake_firecracker() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("api.socket");
    let server = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let join = std::thread::spawn(move || {
        let (s, _) = server.accept().unwrap();
        let mut s = std::fs::File::from(std::os::fd::OwnedFd::from(s));
        let mut b = [0; 4096];
        assert!(s.read(&mut b).unwrap() > 0);
        s.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
    });
    let req = ApiRequest {
        method: "PUT".into(),
        path: "/entropy".into(),
        body: json!({}),
    };
    assert_eq!(
        call(
            path.to_str().unwrap(),
            &req,
            deadline(Duration::from_secs(1)).unwrap()
        )
        .unwrap()
        .status,
        204
    );
    join.join().unwrap();
}
