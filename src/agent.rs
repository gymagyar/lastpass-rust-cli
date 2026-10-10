//! Short-lived memory-only key agent. Credentials never appear in argv.
use crate::{
    crypto::{self, Key},
    store::Store,
};
use anyhow::{Context, Result, bail, ensure};
use std::{
    io::{Read, Write},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub fn request(store: &Store, token: &str, operation: u8) -> Result<Option<Key>> {
    use std::net::{SocketAddr, TcpStream};
    let address: SocketAddr = std::fs::read_to_string(store.path("agent.addr"))
        .context("Vault is locked")?
        .trim()
        .parse()
        .context("Invalid agent address")?;
    ensure!(
        address.ip().is_loopback() && address.is_ipv4(),
        "Agent must listen only on IPv4 loopback"
    );
    let mut stream =
        TcpStream::connect_timeout(&address, Duration::from_secs(2)).context("Vault is locked")?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let token = hex::decode(token).context("Invalid local agent token")?;
    ensure!(token.len() == 32, "Invalid local agent token");
    stream.write_all(&token)?;
    stream.write_all(&[operation])?;
    let mut status = [0];
    stream.read_exact(&mut status)?;
    ensure!(status[0] == 1, "Vault is locked");
    if operation == b'K' {
        let mut key = Zeroizing::new([0; 32]);
        stream.read_exact(&mut *key)?;
        Ok(Some(key))
    } else {
        Ok(None)
    }
}

pub fn start(store: &Store, key: &[u8; 32], timeout: u64) -> Result<String> {
    {
        if let Ok(m) = store.metadata() {
            let _ = request(store, &m.agent_token, b'L');
            for _ in 0..100 {
                if !store.path("agent.addr").exists() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        let token = crypto::random_bytes::<32>();
        let mut child = Command::new(std::env::current_exe()?)
            .arg("--data-dir")
            .arg(&store.dir)
            .arg("__agent")
            .arg(timeout.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .env_remove("LPASS_PASSWORD")
            .env_remove("LPASS_TEST_PASSWORD")
            .spawn()
            .context("Could not start memory agent")?;
        let mut stdin = child.stdin.take().context("Agent pipe unavailable")?;
        stdin.write_all(key)?;
        stdin.write_all(&token)?;
        drop(stdin);
        let token = hex::encode(token);
        for _ in 0..100 {
            if request(store, &token, b'P').is_ok() {
                return Ok(token);
            }
            if let Some(status) = child.try_wait()? {
                bail!("Memory agent exited: {status}");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = child.kill();
        bail!("Memory agent did not start")
    }
}
pub fn serve(store: &Store, timeout: u64) -> Result<()> {
    use std::{fs, net::TcpListener};
    let mut key = Zeroizing::new([0; 32]);
    let mut token = Zeroizing::new([0; 32]);
    std::io::stdin().read_exact(&mut *key)?;
    std::io::stdin().read_exact(&mut *token)?;
    let path = store.path("agent.addr");
    let listener =
        TcpListener::bind("127.0.0.1:0").context("Could not bind loopback memory agent")?;
    store.atomic_write("agent.addr", listener.local_addr()?.to_string().as_bytes())?;
    listener.set_nonblocking(true)?;
    let mut last = Instant::now();
    let result = (|| -> Result<()> {
        loop {
            if timeout > 0 && last.elapsed() >= Duration::from_secs(timeout) {
                break;
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
                    stream.set_write_timeout(Some(Duration::from_secs(1)))?;
                    let mut input = Zeroizing::new([0; 33]);
                    if stream.read_exact(&mut *input).is_err() {
                        continue;
                    }
                    // Constant-time token comparison.
                    let diff = input[..32]
                        .iter()
                        .zip(token.iter())
                        .fold(0u8, |d, (a, b)| d | (a ^ b));
                    if diff != 0 {
                        let _ = stream.write_all(&[0]);
                        continue;
                    }
                    match input[32] {
                        b'K' => {
                            last = Instant::now();
                            let _ = stream.write_all(&[1]);
                            let _ = stream.write_all(&*key);
                        }
                        b'P' => {
                            let _ = stream.write_all(&[1]);
                        }
                        b'L' => {
                            let _ = stream.write_all(&[1]);
                            break;
                        }
                        _ => {
                            let _ = stream.write_all(&[0]);
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(20))
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    })();
    drop(listener);
    let _ = fs::remove_file(path);
    result
}
