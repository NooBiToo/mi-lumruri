//! mi-tt-dns: DoH/DoT-прокси для dnsmasq роутера.
//!
//! dnsmasq отправляет сюда вопросы для доменов, которые не идут через туннель (`server=127.0.0.1#порт`), прокси
//! передаёт их выбранному серверу по DNS-over-HTTPS (HTTP/1.1, keep-alive) или DNS-over-TLS в постоянных соединениях.
//! Сервер задаётся адресом IP, поэтому для запуска DNS не нужен. Если сервер недоступен (нет связи, блокировка или
//! часы роутера после загрузки ещё неверные и сертификат не проходит проверку), вопрос уходит к DNS провайдера из
//! resolv-файла: без этого роутер не смог бы ни синхронизировать часы, ни открыть ни одного сайта.
//! TLS — rustls с криптографией RustCrypto (чистый Rust, без C), корневые сертификаты — webpki-roots.
//!
//!   mi-tt-dns --listen 127.0.0.1:5453 --doh https://cloudflare-dns.com/dns-query --ip 1.1.1.1 --ip 1.0.0.1 \
//!             [--fallback /tmp/resolv.conf.auto] [--status /tmp/mi-trusttunnel/run/dns-proxy.json]
//!   mi-tt-dns --listen … --dot dns.quad9.net --ip 9.9.9.9 …
//!   mi-tt-dns --probe 127.0.0.1:5453 example.com   — один вопрос A, код возврата 0 при ответе
//!   mi-tt-dns --version

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const FALLBACK_TIMEOUT: Duration = Duration::from_secs(2);
const WORKERS: usize = 8;
const MAX_MSG: usize = 4096;

#[derive(Clone, Copy, PartialEq)]
enum Proto {
    Doh,
    Dot,
}

struct Upstream {
    proto: Proto,
    /// Метка сокетов (SO_MARK): 0 — без метки; иначе соединения идут по правилу `ip rule fwmark` (в туннель).
    mark: u32,
    /// Имя сервера: SNI и проверка сертификата, у DoH — ещё и заголовок Host.
    host: String,
    /// Путь DoH (`/dns-query`); у DoT не используется.
    path: String,
    addrs: Vec<SocketAddr>,
    tls: Arc<ClientConfig>,
}

type Tls = StreamOwned<ClientConnection, TcpStream>;

/// Простаивающие соединения с сервером: берётся любое, после ответа возвращается.
struct Pool {
    up: Upstream,
    idle: Mutex<Vec<BufReader<Tls>>>,
    /// Следующий адрес для нового соединения (по кругу при сбоях).
    next: AtomicU64,
}

#[derive(Default)]
struct Stats {
    queries: AtomicU64,
    upstream_ok: AtomicU64,
    fallback: AtomicU64,
    failed: AtomicU64,
    last_ok: AtomicU64,
    last_error: Mutex<String>,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl Pool {
    fn connect(&self) -> Result<BufReader<Tls>, String> {
        let n = self.up.addrs.len();
        let mut last = String::new();
        for _ in 0..n {
            let a = self.up.addrs[(self.next.fetch_add(1, Ordering::Relaxed) as usize) % n];
            match self.connect_to(a) {
                Ok(s) => return Ok(s),
                Err(e) => last = format!("{a}: {e}"),
            }
        }
        Err(last)
    }

    fn connect_to(&self, a: SocketAddr) -> Result<BufReader<Tls>, String> {
        let tcp = if self.up.mark == 0 { TcpStream::connect_timeout(&a, CONNECT_TIMEOUT).map_err(|e| e.to_string())? } else { connect_marked(a, self.up.mark)? };
        tcp.set_read_timeout(Some(IO_TIMEOUT)).ok();
        tcp.set_write_timeout(Some(IO_TIMEOUT)).ok();
        tcp.set_nodelay(true).ok();
        let name = ServerName::try_from(self.up.host.clone()).map_err(|e| e.to_string())?;
        let conn = ClientConnection::new(self.up.tls.clone(), name).map_err(|e| e.to_string())?;
        let mut s = StreamOwned::new(conn, tcp);
        // рукопожатие сразу: ошибка сертификата видна здесь, а не на первом вопросе
        while s.conn.is_handshaking() {
            s.conn.complete_io(&mut s.sock).map_err(|e| format!("TLS: {e}"))?;
        }
        Ok(BufReader::new(s))
    }

    /// Вопрос серверу: сначала по готовому соединению, при сбое — по новому (соединение могло закрыться сервером).
    fn query(&self, q: &[u8]) -> Result<Vec<u8>, String> {
        let pooled = self.idle.lock().ok().and_then(|mut v| v.pop());
        if let Some(mut s) = pooled {
            if let Ok(r) = self.exchange(&mut s, q) {
                self.put(s);
                return Ok(r);
            }
        }
        let mut s = self.connect()?;
        let r = self.exchange(&mut s, q)?;
        self.put(s);
        Ok(r)
    }

    fn put(&self, s: BufReader<Tls>) {
        if let Ok(mut v) = self.idle.lock() {
            if v.len() < WORKERS {
                v.push(s);
            }
        }
    }

    fn exchange(&self, s: &mut BufReader<Tls>, q: &[u8]) -> Result<Vec<u8>, String> {
        match self.up.proto {
            Proto::Dot => {
                let mut out = Vec::with_capacity(q.len() + 2);
                out.extend_from_slice(&(q.len() as u16).to_be_bytes());
                out.extend_from_slice(q);
                s.get_mut().write_all(&out).map_err(|e| e.to_string())?;
                s.get_mut().flush().map_err(|e| e.to_string())?;
                let mut len = [0u8; 2];
                s.read_exact(&mut len).map_err(|e| e.to_string())?;
                let n = u16::from_be_bytes(len) as usize;
                let mut r = vec![0u8; n];
                s.read_exact(&mut r).map_err(|e| e.to_string())?;
                Ok(r)
            }
            Proto::Doh => {
                let head = format!(
                    "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: {}\r\n\r\n",
                    self.up.path, self.up.host, q.len()
                );
                let w = s.get_mut();
                w.write_all(head.as_bytes()).map_err(|e| e.to_string())?;
                w.write_all(q).map_err(|e| e.to_string())?;
                w.flush().map_err(|e| e.to_string())?;
                read_http(s)
            }
        }
    }
}

/// Соединение с меткой сокета (SO_MARK) — до connect: по ней ядро выбирает маршрут (таблица туннеля) и адрес отправителя.
#[cfg(target_os = "linux")]
fn connect_marked(a: SocketAddr, mark: u32) -> Result<TcpStream, String> {
    let s = socket2::Socket::new(socket2::Domain::for_address(a), socket2::Type::STREAM, Some(socket2::Protocol::TCP)).map_err(|e| e.to_string())?;
    s.set_mark(mark).map_err(|e| format!("метка сокета: {e}"))?;
    s.connect_timeout(&a.into(), CONNECT_TIMEOUT).map_err(|e| e.to_string())?;
    Ok(TcpStream::from(s))
}

#[cfg(not(target_os = "linux"))]
fn connect_marked(_a: SocketAddr, _mark: u32) -> Result<TcpStream, String> {
    Err("метка сокета (--mark) есть только в Linux".into())
}

/// Ответ HTTP/1.1: статус 200, тело по Content-Length или chunked. Соединение остаётся открытым.
fn read_http<R: BufRead>(s: &mut R) -> Result<Vec<u8>, String> {
    let mut line = String::new();
    s.read_line(&mut line).map_err(|e| e.to_string())?;
    if line.is_empty() {
        return Err("сервер закрыл соединение".into());
    }
    let status = line.split_whitespace().nth(1).unwrap_or("").to_string();
    let (mut len, mut chunked, mut close) = (None, false, false);
    loop {
        line.clear();
        s.read_line(&mut line).map_err(|e| e.to_string())?;
        let l = line.trim_end();
        if l.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
            match k.as_str() {
                "content-length" => len = v.parse::<usize>().ok(),
                "transfer-encoding" => chunked = v.eq_ignore_ascii_case("chunked"),
                "connection" => close = v.eq_ignore_ascii_case("close"),
                _ => {}
            }
        }
    }
    let body = if chunked {
        let mut b = Vec::new();
        loop {
            line.clear();
            s.read_line(&mut line).map_err(|e| e.to_string())?;
            let n = usize::from_str_radix(line.trim().split(';').next().unwrap_or(""), 16).map_err(|_| "ответ chunked не разобран")?;
            if n == 0 {
                line.clear();
                s.read_line(&mut line).ok();
                break;
            }
            if b.len() + n > MAX_MSG * 16 {
                return Err("ответ слишком большой".into());
            }
            let mut c = vec![0u8; n + 2];
            s.read_exact(&mut c).map_err(|e| e.to_string())?;
            b.extend_from_slice(&c[..n]);
        }
        b
    } else if let Some(n) = len {
        if n > MAX_MSG * 16 {
            return Err("ответ слишком большой".into());
        }
        let mut b = vec![0u8; n];
        s.read_exact(&mut b).map_err(|e| e.to_string())?;
        b
    } else {
        // без длины — тело до закрытия соединения (так отвечают ошибкой, например «505» у серверов только с HTTP/2)
        let mut b = Vec::new();
        s.take((MAX_MSG * 16) as u64).read_to_end(&mut b).map_err(|e| e.to_string())?;
        b
    };
    if status != "200" {
        return Err(format!("HTTP {status}"));
    }
    // «Connection: close»: ответ годен, а следующий вопрос по этому соединению не пройдёт и откроет новое
    let _ = close;
    Ok(body)
}

/// Запасной путь — обычный DNS провайдера (nameserver из resolv-файла, кроме локальных адресов).
fn fallback(resolv: &str, q: &[u8]) -> Result<Vec<u8>, String> {
    let text = std::fs::read_to_string(resolv).map_err(|e| format!("{resolv}: {e}"))?;
    let servers: Vec<IpAddr> = text
        .lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .filter_map(|v| v.trim().parse::<IpAddr>().ok())
        .filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
        .collect();
    if servers.is_empty() {
        return Err("в resolv-файле нет DNS провайдера".into());
    }
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(FALLBACK_TIMEOUT)).ok();
    let mut last = String::new();
    for ip in servers {
        let a = SocketAddr::new(ip, 53);
        if let Err(e) = sock.send_to(q, a) {
            last = e.to_string();
            continue;
        }
        let mut buf = [0u8; MAX_MSG];
        match sock.recv_from(&mut buf) {
            Ok((n, from)) if from == a && n >= 2 && buf[..2] == q[..2] => return Ok(buf[..n].to_vec()),
            Ok(_) => last = "чужой ответ".into(),
            Err(e) => last = e.to_string(),
        }
    }
    Err(last)
}

/// SERVFAIL на вопрос: тот же ID и вопрос, флаги QR+RD+RA, RCODE 2.
fn servfail(q: &[u8]) -> Vec<u8> {
    let mut r = q.to_vec();
    if r.len() >= 12 {
        r[2] = 0x80 | (q[2] & 0x01);
        r[3] = 0x82;
        r[6..12].fill(0);
    }
    r
}

struct Proxy {
    pool: Pool,
    fallback: Option<String>,
    stats: Stats,
}

impl Proxy {
    fn answer(&self, q: &[u8]) -> Vec<u8> {
        self.stats.queries.fetch_add(1, Ordering::Relaxed);
        if q.len() < 12 {
            return Vec::new();
        }
        match self.pool.query(q) {
            Ok(r) if r.len() >= 2 && r[..2] == q[..2] => {
                self.stats.upstream_ok.fetch_add(1, Ordering::Relaxed);
                self.stats.last_ok.store(now(), Ordering::Relaxed);
                return r;
            }
            Ok(_) => self.note("сервер вернул чужой ответ".into()),
            Err(e) => self.note(e),
        }
        if let Some(f) = &self.fallback {
            if let Ok(r) = fallback(f, q) {
                self.stats.fallback.fetch_add(1, Ordering::Relaxed);
                return r;
            }
        }
        self.stats.failed.fetch_add(1, Ordering::Relaxed);
        servfail(q)
    }

    fn note(&self, e: String) {
        if let Ok(mut l) = self.stats.last_error.lock() {
            *l = e;
        }
    }

    fn status_json(&self, upstream: &str) -> String {
        let s = &self.stats;
        let err = s.last_error.lock().map(|e| e.clone()).unwrap_or_default();
        let last_ok = s.last_ok.load(Ordering::Relaxed);
        format!(
            "{{\"at\":{},\"upstream\":{},\"queries\":{},\"upstream_ok\":{},\"fallback\":{},\"failed\":{},\"last_ok\":{},\"last_error\":{}}}\n",
            now(),
            json_str(upstream),
            s.queries.load(Ordering::Relaxed),
            s.upstream_ok.load(Ordering::Relaxed),
            s.fallback.load(Ordering::Relaxed),
            s.failed.load(Ordering::Relaxed),
            if last_ok == 0 { "null".to_string() } else { last_ok.to_string() },
            if err.is_empty() { "null".to_string() } else { json_str(&err) }
        )
    }
}

fn json_str(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => o.push(' '),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn tls_config(alpn: &[u8]) -> Result<Arc<ClientConfig>, String> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut c = ClientConfig::builder_with_provider(Arc::new(rustls_rustcrypto::provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    c.alpn_protocols = vec![alpn.to_vec()];
    Ok(Arc::new(c))
}

struct Args {
    listen: SocketAddr,
    proto: Proto,
    target: String,
    ips: Vec<IpAddr>,
    fallback: Option<String>,
    status: Option<String>,
    mark: u32,
}

fn usage(m: &str) -> ! {
    eprintln!("mi-tt-dns: {m}\n  mi-tt-dns --listen 127.0.0.1:5453 (--doh URL | --dot HOST[:port]) --ip IP [--ip IP…] [--fallback resolv] [--status file] [--mark 0x4000]\n  mi-tt-dns --probe 127.0.0.1:5453 example.com\n  mi-tt-dns --version");
    std::process::exit(2)
}

fn parse_args(v: &[String]) -> Args {
    let mut a = Args { listen: "127.0.0.1:5453".parse().unwrap(), proto: Proto::Doh, target: String::new(), ips: Vec::new(), fallback: None, status: None, mark: 0 };
    let mut it = v.iter();
    while let Some(k) = it.next() {
        let mut val = || it.next().cloned().unwrap_or_else(|| usage(&format!("{k}: нет значения")));
        match k.as_str() {
            "--listen" => a.listen = val().parse().unwrap_or_else(|_| usage("--listen: адрес:порт")),
            "--doh" => { a.proto = Proto::Doh; a.target = val(); }
            "--dot" => { a.proto = Proto::Dot; a.target = val(); }
            "--ip" => a.ips.push(val().parse().unwrap_or_else(|_| usage("--ip: IP-адрес"))),
            "--fallback" => a.fallback = Some(val()),
            "--status" => a.status = Some(val()),
            "--mark" => {
                let v = val();
                a.mark = v.strip_prefix("0x").map_or_else(|| v.parse().ok(), |h| u32::from_str_radix(h, 16).ok()).unwrap_or_else(|| usage("--mark: число, например 0x4000"));
            }
            _ => usage(&format!("неизвестный параметр {k}")),
        }
    }
    if a.target.is_empty() || a.ips.is_empty() {
        usage("нужны --doh или --dot и хотя бы один --ip");
    }
    a
}

/// Сервер из параметров: DoH — https://host[:port]/path, DoT — host[:port] (порт 853).
fn upstream(a: &Args) -> Result<Upstream, String> {
    let (host, port, path) = match a.proto {
        Proto::Doh => {
            let rest = a.target.strip_prefix("https://").ok_or("--doh: ссылка https://…")?;
            let (hp, path) = rest.split_once('/').map(|(h, p)| (h, format!("/{p}"))).unwrap_or((rest, "/dns-query".into()));
            let (h, p) = hp.rsplit_once(':').and_then(|(h, p)| p.parse::<u16>().ok().map(|p| (h, p))).unwrap_or((hp, 443));
            (h.to_string(), p, path)
        }
        Proto::Dot => {
            let (h, p) = a.target.rsplit_once(':').and_then(|(h, p)| p.parse::<u16>().ok().map(|p| (h, p))).unwrap_or((a.target.as_str(), 853));
            (h.to_string(), p, String::new())
        }
    };
    if host.is_empty() || !host.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-') {
        return Err(format!("имя сервера «{host}» не подходит"));
    }
    let tls = tls_config(if a.proto == Proto::Doh { b"http/1.1" } else { b"dot" })?;
    Ok(Upstream { proto: a.proto, mark: a.mark, host, path, addrs: a.ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect(), tls })
}

/// Вопрос A о домене: ID случайный от времени, флаг RD.
fn build_query(name: &str) -> Vec<u8> {
    let id = (now() as u16) ^ 0x5a5a;
    let mut q = vec![(id >> 8) as u8, id as u8, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for l in name.trim_end_matches('.').split('.') {
        q.push(l.len() as u8);
        q.extend_from_slice(l.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    q
}

fn probe(addr: &str, name: &str) -> i32 {
    let Ok(a) = addr.parse::<SocketAddr>() else { return 2 };
    let Ok(s) = UdpSocket::bind("127.0.0.1:0") else { return 1 };
    s.set_read_timeout(Some(Duration::from_secs(8))).ok();
    let q = build_query(name);
    if s.send_to(&q, a).is_err() {
        return 1;
    }
    let mut buf = [0u8; MAX_MSG];
    match s.recv(&mut buf) {
        Ok(n) if n >= 4 && buf[..2] == q[..2] && buf[3] & 0x0f == 0 => {
            println!("ok");
            0
        }
        Ok(n) if n >= 4 => {
            println!("rcode {}", buf[3] & 0x0f);
            1
        }
        _ => {
            println!("нет ответа");
            1
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--version") => {
            println!("mi-tt-dns {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        Some("--probe") => std::process::exit(probe(args.get(1).map(String::as_str).unwrap_or(""), args.get(2).map(String::as_str).unwrap_or("example.com"))),
        _ => {}
    }
    let a = parse_args(&args);
    let up = upstream(&a).unwrap_or_else(|e| usage(&e));
    let label = format!("{}{}", if a.proto == Proto::Doh { "doh " } else { "dot " }, a.target);
    let proxy = Arc::new(Proxy { pool: Pool { up, idle: Mutex::new(Vec::new()), next: AtomicU64::new(0) }, fallback: a.fallback.clone(), stats: Stats::default() });

    let udp = UdpSocket::bind(a.listen).unwrap_or_else(|e| usage(&format!("{}: {e}", a.listen)));
    let tcp = TcpListener::bind(a.listen).unwrap_or_else(|e| usage(&format!("{} (TCP): {e}", a.listen)));
    eprintln!("mi-tt-dns: {label} на {}", a.listen);

    // состояние для панели и диагностики раз в 15 секунд
    if let Some(path) = a.status.clone() {
        let p = proxy.clone();
        let label = label.clone();
        std::thread::spawn(move || loop {
            let tmp = format!("{path}.t");
            if std::fs::write(&tmp, p.status_json(&label)).is_ok() {
                let _ = std::fs::rename(&tmp, &path);
            }
            std::thread::sleep(Duration::from_secs(15));
        });
    }

    // TCP (dnsmasq переходит на него при усечённых ответах): поток на соединение, вопросы с длиной впереди
    {
        let p = proxy.clone();
        std::thread::spawn(move || {
            for c in tcp.incoming().flatten() {
                let p = p.clone();
                std::thread::spawn(move || {
                    let mut c = c;
                    c.set_read_timeout(Some(Duration::from_secs(10))).ok();
                    loop {
                        let mut len = [0u8; 2];
                        if c.read_exact(&mut len).is_err() {
                            break;
                        }
                        let n = u16::from_be_bytes(len) as usize;
                        let mut q = vec![0u8; n];
                        if c.read_exact(&mut q).is_err() {
                            break;
                        }
                        let r = p.answer(&q);
                        let mut out = (r.len() as u16).to_be_bytes().to_vec();
                        out.extend_from_slice(&r);
                        if c.write_all(&out).is_err() {
                            break;
                        }
                    }
                });
            }
        });
    }

    // UDP: приём в одном потоке, ответы — в пуле рабочих потоков
    let (tx, rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>();
    let rx = Arc::new(Mutex::new(rx));
    for _ in 0..WORKERS {
        let (p, rx, sock) = (proxy.clone(), rx.clone(), udp.try_clone().expect("udp"));
        std::thread::spawn(move || loop {
            let job = rx.lock().ok().and_then(|r| r.recv().ok());
            let Some((q, from)) = job else { return };
            let r = p.answer(&q);
            if !r.is_empty() {
                let _ = sock.send_to(&r, from);
            }
        });
    }
    let mut buf = [0u8; MAX_MSG];
    loop {
        match udp.recv_from(&mut buf) {
            Ok((n, from)) => {
                let _ = tx.send((buf[..n].to_vec(), from));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_response_content_length_and_chunked() {
        let r = b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 3\r\n\r\nabcHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nde\r\n1\r\nf\r\n0\r\n\r\n";
        let mut s = BufReader::new(&r[..]);
        assert_eq!(read_http(&mut s).unwrap(), b"abc");
        assert_eq!(read_http(&mut s).unwrap(), b"def");
        let mut bad = BufReader::new(&b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"[..]);
        assert_eq!(read_http(&mut bad).unwrap_err(), "HTTP 400");
    }

    #[test]
    fn servfail_keeps_id_and_question() {
        let q = build_query("example.com");
        let r = servfail(&q);
        assert_eq!((r[..2] == q[..2], r[2] & 0x80, r[3] & 0x0f, &r[12..]), (true, 0x80, 2, &q[12..]));
    }

    #[test]
    fn upstream_from_args() {
        let a = parse_args(&["--doh".into(), "https://dns.example:8443/q".into(), "--ip".into(), "203.0.113.1".into()]);
        let u = upstream(&a).unwrap();
        assert_eq!((u.host.as_str(), u.path.as_str(), u.addrs[0].port()), ("dns.example", "/q", 8443));
        let d = parse_args(&["--dot".into(), "dns.quad9.net".into(), "--ip".into(), "9.9.9.9".into()]);
        assert_eq!(upstream(&d).unwrap().addrs[0], "9.9.9.9:853".parse().unwrap());
    }
}
