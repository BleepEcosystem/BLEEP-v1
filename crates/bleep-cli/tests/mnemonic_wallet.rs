use bleep_core::transaction::ZKTransaction;
use bleep_wallet_core::wallet::WalletManager;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::Command,
    thread,
    time::{Duration, Instant},
};

#[test]
fn cli_mnemonic_round_trip_restores_a_signing_wallet() {
    let temp_dir = tempfile::tempdir().expect("temporary home directory");
    let created_home = temp_dir.path().join("created");
    let restored_home = temp_dir.path().join("restored");
    std::fs::create_dir_all(&created_home).unwrap();
    std::fs::create_dir_all(&restored_home).unwrap();

    let create_output = Command::new(env!("CARGO_BIN_EXE_bleep-cli"))
        .args(["wallet", "create"])
        .env("HOME", &created_home)
        .env("BLEEP_WALLET_PASSWORD", "test-wallet-password")
        .env("BLEEP_RPC", "http://127.0.0.1:1")
        .output()
        .expect("run CLI wallet create");
    assert!(
        create_output.status.success(),
        "wallet create failed: {}",
        String::from_utf8_lossy(&create_output.stderr)
    );
    let create_stdout = String::from_utf8(create_output.stdout).unwrap();
    let phrase = create_stdout
        .split_once("Recovery phrase (write this down; shown only once):\n")
        .and_then(|(_, rest)| rest.lines().next())
        .expect("CLI create output should display its recovery phrase")
        .trim()
        .to_owned();

    let import_output = Command::new(env!("CARGO_BIN_EXE_bleep-cli"))
        .args(["wallet", "import", &phrase])
        .env("HOME", &restored_home)
        .env("BLEEP_WALLET_PASSWORD", "test-wallet-password")
        .env("BLEEP_RPC", "http://127.0.0.1:1")
        .output()
        .expect("run CLI wallet import");
    assert!(
        import_output.status.success(),
        "wallet import failed: {}",
        String::from_utf8_lossy(&import_output.stderr)
    );

    let created_manager =
        WalletManager::load_or_create_at(created_home.join(".bleep/wallets.json")).unwrap();
    let restored_manager =
        WalletManager::load_or_create_at(restored_home.join(".bleep/wallets.json")).unwrap();
    let created = &created_manager.list_wallets()[0];
    let restored = &restored_manager.list_wallets()[0];
    assert_eq!(created.derivation_version, 2);
    assert_eq!(restored.derivation_version, 2);
    assert!(created.address().starts_with("BLEEP2"));
    assert_eq!(created.address(), restored.address());
    assert_eq!(created.falcon_keys, restored.falcon_keys);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let rpc = format!("http://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(120);
        while Instant::now() < deadline {
            let (mut stream, _) = match listener.accept() {
                Ok(connection) => connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(error) => panic!("mock RPC accept failed: {error}"),
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let request = read_http_request(&mut stream);
            let request_text = String::from_utf8_lossy(&request);
            let (status, body) = if request_text.starts_with("GET /rpc/tx/nonce/") {
                ("200 OK", r#"{"nonce":0}"#.to_string())
            } else if request_text.starts_with("POST /rpc/tx ") {
                assert!(request_text
                    .lines()
                    .any(|line| line.eq_ignore_ascii_case("authorization: Bearer test-session")));
                let body_start = request.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
                let tx: ZKTransaction = serde_json::from_slice(&request[body_start..]).unwrap();
                assert!(tx.sender.starts_with("BLEEP2"));
                assert!(tx.verify_account_authorization());
                (
                    "200 OK",
                    r#"{"status":"accepted","tx_id":"mnemonic-round-trip"}"#.to_string(),
                )
            } else {
                panic!(
                    "unexpected mock RPC request: {}",
                    request_text.lines().next().unwrap_or("")
                );
            };

            write!(
                stream,
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
            stream.flush().unwrap();
            if request_text.starts_with("POST /rpc/tx ") {
                return;
            }
        }
        panic!("timed out waiting for CLI transaction requests");
    });

    let tx_output = Command::new(env!("CARGO_BIN_EXE_bleep-cli"))
        .args(["tx", "send", "BLEEP2recipient", "123"])
        .env("HOME", &restored_home)
        .env("BLEEP_WALLET_PASSWORD", "test-wallet-password")
        .env("BLEEP_JWT_TOKEN", "test-session")
        .env("BLEEP_RPC", rpc)
        .output()
        .expect("run CLI transaction send");
    assert!(
        tx_output.status.success(),
        "tx send failed: {}",
        String::from_utf8_lossy(&tx_output.stderr)
    );
    assert!(String::from_utf8_lossy(&tx_output.stdout).contains("mnemonic-round-trip"));
    server.join().unwrap();
}

fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let count = stream.read(&mut buffer).expect("read mock RPC request");
        assert_ne!(count, 0, "client closed before completing its request");
        request.extend_from_slice(&buffer[..count]);
        let Some(header_end) = request.windows(4).position(|w| w == b"\r\n\r\n") else {
            continue;
        };
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        if request.len() >= header_end + 4 + content_length {
            return request;
        }
    }
}
