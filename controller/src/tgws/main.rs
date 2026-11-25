//! mi-tt-tgws: прозрачный прокси Telegram через WebSocket (модуль tgws).
//!
//! iptables (nat PREROUTING, REDIRECT) заворачивает TCP устройств к адресам Telegram на этот порт. Прокси узнаёт
//! исходный адрес (SO_ORIGINAL_DST), читает начало потока клиента Telegram и, если это MTProto к дата-центру, для
//! которого известен вход WebSocket, ведёт соединение через `wss://kws<dc>.web.telegram.org/apiws` (TLS к адресу из
//! `--dc`, имя — в SNI): для DPI это HTTPS к веб-версии Telegram. Клиенту ничего настраивать не нужно — в отличие от
//! MTProto-прокси (идея и протокол — как у Flowseal/tg-ws-proxy, MIT), здесь нет секрета: клиент думает, что говорит с
//! дата-центром напрямую.
//!
//! Поток клиента — обфусцированный транспорт MTProto (64 байта начала, AES-256-CTR без секрета) или открытый
//! abridged/intermediate/padded. К Telegram прокси отправляет своё начало (тег протокола и номер DC, отрицательный —
//! медиа) и перешифровывает поток в обе стороны; пакеты MTProto — по одному в кадре WebSocket.
//!
//! Запасной путь — когда вход WebSocket для DC не задан, недоступен (последняя неудача — минута тишины) или поток не
//! MTProto (сайты Telegram на тех же адресах): соединение к исходному адресу как есть — через туннель VPN
//! (`--via-device mitt<n>`, при одном туннеле ещё `--via-mark`) или напрямую.
//!
//!   mi-tt-tgws --listen 0.0.0.0:18443 [--dc 2:149.154.167.220 …] [--via-device mitt0 [--via-mark 0x4000]]
//!              [--status /tmp/mi-lumruri/run/tgws.json]
//!   mi-tt-tgws --probe 2   — проверка: req_pq через WebSocket к DC, код 0 при ответе resPQ
//!   mi-tt-tgws --version

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aes::cipher::{KeyIvInit, StreamCipher};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};

type Ctr = ctr::Ctr128BE<aes::Aes256>;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// После неудачи WebSocket к DC — столько времени сразу запасной путь (без ожидания тайм-аута на каждом соединении).
const WS_COOLDOWN: Duration = Duration::from_secs(60);
const MAX_FRAME: usize = 16 * 1024 * 1024;
const TAG_ABRIDGED: [u8; 4] = [0xef; 4];
/// Входы WebSocket дата-центров по умолчанию.
const DEFAULT_DCS: [(i16, Ipv4Addr); 5] = [
    (1, Ipv4Addr::new(149, 154, 174, 100)),
    (2, Ipv4Addr::new(149, 154, 167, 220)),
    (3, Ipv4Addr::new(149, 154, 174, 100)),
    (4, Ipv4Addr::new(149, 154, 167, 220)),
    (5, Ipv4Addr::new(149, 154, 170, 100)),
];
const TAG_INTERMEDIATE: [u8; 4] = [0xee; 4];
const TAG_PADDED: [u8; 4] = [0xdd; 4];

// ---------- обфусцированный транспорт MTProto ----------

fn ctr(key: &[u8], iv: &[u8]) -> Ctr {
    Ctr::new(key.into(), iv.into())
}

/// Начало обфусцированного потока клиента (64 байта, без секрета): шифр «от клиента» (уже прошедший 64 байта),
/// шифр «к клиенту», тег протокола и индекс DC (отрицательный — медиа). None — это не MTProto.
pub struct ClientObf {
    pub dec: Ctr,
    pub enc: Ctr,
    pub tag: [u8; 4],
    pub dc: i16,
}

pub fn parse_obfuscated(init: &[u8; 64]) -> Option<ClientObf> {
    let mut dec = ctr(&init[8..40], &init[40..56]);
    let mut plain = *init;
    dec.apply_keystream(&mut plain);
    let tag: [u8; 4] = plain[56..60].try_into().ok()?;
    if tag != TAG_ABRIDGED && tag != TAG_INTERMEDIATE && tag != TAG_PADDED {
        return None;
    }
    let dc = i16::from_le_bytes([plain[60], plain[61]]);
    let mut rev = [0u8; 48];
    rev.copy_from_slice(&init[8..56]);
    rev.reverse();
    let enc = ctr(&rev[..32], &rev[32..48]);
    Some(ClientObf { dec, enc, tag, dc })
}

/// Своё начало к Telegram: 56 случайных байт и зашифрованные тег, DC и 2 случайных байта. Шифры: к Telegram (уже
/// прошедший 64 байта) и от Telegram.
pub fn relay_init(tag: [u8; 4], dc: i16, mut random: impl FnMut(&mut [u8])) -> ([u8; 64], Ctr, Ctr) {
    let mut init = [0u8; 64];
    loop {
        random(&mut init);
        let s4: [u8; 4] = init[..4].try_into().unwrap_or_default();
        let bad = init[0] == 0xef
            || [*b"HEAD", *b"POST", *b"GET ", *b"OPTI", TAG_INTERMEDIATE, TAG_PADDED, [0x16, 0x03, 0x01, 0x02]].contains(&s4)
            || init[4..8] == [0, 0, 0, 0];
        if !bad {
            break;
        }
    }
    init[56..60].copy_from_slice(&tag);
    init[60..62].copy_from_slice(&dc.to_le_bytes());
    let mut enc = ctr(&init[8..40], &init[40..56]);
    let mut full = init;
    enc.apply_keystream(&mut full);
    init[56..64].copy_from_slice(&full[56..64]);
    let mut rev = [0u8; 48];
    rev.copy_from_slice(&init[8..56]);
    rev.reverse();
    let dec = ctr(&rev[..32], &rev[32..48]);
    (init, enc, dec)
}

/// Дата-центр по адресу (открытый транспорт не называет DC): известные подсети Telegram.
pub fn dc_of_ip(ip: Ipv4Addr) -> Option<i16> {
    let o = ip.octets();
    match (o[0], o[1], o[2], o[3]) {
        (149, 154, 175, 100..=119) => Some(3),
        (149, 154, 175, _) => Some(1),
        (149, 154, 167, 91..=92) | (149, 154, 166, _) | (149, 154, 165, _) => Some(4),
        (149, 154, 167, _) | (149, 154, 164, _) => Some(2),
        (149, 154, 171, _) | (91, 108, 56..=59, _) => Some(5),
        (91, 105, 192..=193, _) => Some(203),
        _ => None,
    }
}

/// Разбор открытого потока на пакеты MTProto: каждый пакет — отдельный кадр WebSocket. Непонятная длина — дальше
/// поток идёт как есть.
pub struct Splitter {
    tag: [u8; 4],
    buf: Vec<u8>,
    off: bool,
}

impl Splitter {
    pub fn new(tag: [u8; 4]) -> Self {
        Splitter { tag, buf: Vec::new(), off: false }
    }
    pub fn push(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        if self.off {
            return vec![data.to_vec()];
        }
        self.buf.extend_from_slice(data);
        let mut out = Vec::new();
        loop {
            let need = if self.tag == TAG_ABRIDGED {
                let Some(&b) = self.buf.first() else { break };
                if b & 0x7f == 0x7f {
                    if self.buf.len() < 4 {
                        break;
                    }
                    4 + (u32::from_le_bytes([self.buf[1], self.buf[2], self.buf[3], 0]) as usize) * 4
                } else {
                    1 + usize::from(b & 0x7f) * 4
                }
            } else {
                if self.buf.len() < 4 {
                    break;
                }
                4 + (u32::from_le_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) & 0x7fff_ffff) as usize
            };
            if need <= 4 || need > MAX_FRAME {
                // не похоже на пакет — дальше без разбора
                self.off = true;
                out.push(std::mem::take(&mut self.buf));
                break;
            }
            if self.buf.len() < need {
                break;
            }
            out.push(self.buf.drain(..need).collect());
        }
        out
    }
}

// ---------- WebSocket (RFC 6455, клиент) ----------

pub fn ws_frame(opcode: u8, payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
    let mut f = Vec::with_capacity(payload.len() + 14);
    f.push(0x80 | opcode);
    match payload.len() {
        n if n < 126 => f.push(0x80 | n as u8),
        n if n <= 0xffff => {
            f.push(0x80 | 126);
            f.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            f.push(0x80 | 127);
            f.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    f.extend_from_slice(&mask);
    f.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    f
}

/// Кадры из начала буфера: (opcode, fin, данные) и сколько байт прочитано. Неполный кадр — ждать ещё.
pub fn ws_parse(buf: &[u8]) -> Result<Option<(u8, bool, Vec<u8>, usize)>, String> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let (fin, op, masked) = (buf[0] & 0x80 != 0, buf[0] & 0x0f, buf[1] & 0x80 != 0);
    let (mut len, mut pos) = (usize::from(buf[1] & 0x7f), 2);
    if len == 126 {
        if buf.len() < 4 {
            return Ok(None);
        }
        len = usize::from(u16::from_be_bytes([buf[2], buf[3]]));
        pos = 4;
    } else if len == 127 {
        if buf.len() < 10 {
            return Ok(None);
        }
        len = usize::try_from(u64::from_be_bytes(buf[2..10].try_into().unwrap_or_default())).unwrap_or(usize::MAX);
        pos = 10;
    }
    if len > MAX_FRAME {
        return Err("кадр WebSocket слишком большой".into());
    }
    let mask = if masked {
        if buf.len() < pos + 4 {
            return Ok(None);
        }
        let m: [u8; 4] = buf[pos..pos + 4].try_into().unwrap_or_default();
        pos += 4;
        Some(m)
    } else {
        None
    };
    if buf.len() < pos + len {
        return Ok(None);
    }
    let mut data = buf[pos..pos + len].to_vec();
    if let Some(m) = mask {
        data.iter_mut().enumerate().for_each(|(i, b)| *b ^= m[i % 4]);
    }
    Ok(Some((op, fin, data, pos + len)))
}

fn rand_fill(b: &mut [u8]) {
    let _ = getrandom::fill(b);
}
fn rand4() -> [u8; 4] {
    let mut m = [0u8; 4];
    rand_fill(&mut m);
    m
}

// ---------- соединения ----------

struct Cfg {
    dcs: BTreeMap<i16, Ipv4Addr>,
    via_device: Option<String>,
    via_mark: u32,
    tls: Arc<ClientConfig>,
}

#[derive(Default)]
struct Stats {
    active: AtomicU64,
    ws: AtomicU64,
    fallback: AtomicU64,
    ws_errors: AtomicU64,
    last_error: Mutex<String>,
    cooldown: Mutex<BTreeMap<i16, Instant>>,
}

fn connect(a: SocketAddr, device: Option<&str>, mark: u32) -> std::io::Result<TcpStream> {
    #[cfg(target_os = "linux")]
    {
        let s = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
        if mark != 0 {
            s.set_mark(mark)?;
        }
        if let Some(d) = device {
            s.bind_device(Some(d.as_bytes()))?;
        }
        s.connect_timeout(&a.into(), CONNECT_TIMEOUT)?;
        Ok(s.into())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (device, mark);
        TcpStream::connect_timeout(&a, CONNECT_TIMEOUT)
    }
}

#[cfg(target_os = "linux")]
fn original_dst(s: &TcpStream) -> Option<SocketAddrV4> {
    socket2::SockRef::from(s).original_dst().ok()?.as_socket_ipv4()
}
#[cfg(not(target_os = "linux"))]
fn original_dst(_s: &TcpStream) -> Option<SocketAddrV4> {
    None
}

/// Запасной путь: исходный адрес как есть — через туннель или напрямую; уже прочитанное начало отправляется первым.
fn fallback(cfg: &Cfg, client: TcpStream, dst: SocketAddrV4, head: &[u8]) -> Result<(), String> {
    let mut up = connect(SocketAddr::V4(dst), cfg.via_device.as_deref(), cfg.via_mark).map_err(|e| format!("{dst}: {e}"))?;
    up.write_all(head).map_err(|e| e.to_string())?;
    let (mut c2, mut u2) = (client.try_clone().map_err(|e| e.to_string())?, up.try_clone().map_err(|e| e.to_string())?);
    let t = std::thread::spawn(move || {
        let _ = std::io::copy(&mut c2, &mut u2);
        let _ = u2.shutdown(Shutdown::Write);
    });
    let (mut c, mut u) = (client, up);
    let _ = std::io::copy(&mut u, &mut c);
    let _ = c.shutdown(Shutdown::Write);
    let _ = t.join();
    Ok(())
}

/// TLS и WebSocket к `kws<dc>[-1].web.telegram.org` по адресу `ip`.
fn ws_open(cfg: &Cfg, ip: Ipv4Addr, dc: i16) -> Result<(TcpStream, ClientConnection, Vec<u8>), String> {
    let n = dc.unsigned_abs();
    let n = if n == 203 { 2 } else { n };
    let hosts = if dc < 0 { vec![format!("kws{n}-1.web.telegram.org"), format!("kws{n}.web.telegram.org")] } else { vec![format!("kws{n}.web.telegram.org")] };
    let mut last = String::new();
    for host in hosts {
        match ws_try(cfg, ip, &host) {
            Ok(x) => return Ok(x),
            Err(e) => last = format!("{host}: {e}"),
        }
    }
    Err(last)
}

fn ws_try(cfg: &Cfg, ip: Ipv4Addr, host: &str) -> Result<(TcpStream, ClientConnection, Vec<u8>), String> {
    let mut tcp = connect(SocketAddr::V4(SocketAddrV4::new(ip, 443)), None, 0).map_err(|e| e.to_string())?;
    tcp.set_read_timeout(Some(HANDSHAKE_TIMEOUT)).map_err(|e| e.to_string())?;
    let name = ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
    let mut conn = ClientConnection::new(cfg.tls.clone(), name).map_err(|e| e.to_string())?;
    while conn.is_handshaking() {
        conn.complete_io(&mut tcp).map_err(|e| format!("TLS: {e}"))?;
    }
    let mut key = [0u8; 16];
    rand_fill(&mut key);
    let req = format!(
        "GET /apiws HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: binary\r\n\r\n",
        data_encoding::BASE64.encode(&key)
    );
    conn.writer().write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    while conn.wants_write() {
        conn.write_tls(&mut tcp).map_err(|e| e.to_string())?;
    }
    // ответ на Upgrade: до пустой строки; что пришло после — уже кадры
    let mut resp = Vec::new();
    let end = loop {
        if let Some(p) = resp.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        if resp.len() > 16 * 1024 {
            return Err("ответ WebSocket слишком длинный".into());
        }
        let mut b = [0u8; 4096];
        let n = tls_read(&mut conn, &mut tcp, &mut b)?;
        if n == 0 {
            return Err("сервер закрыл соединение".into());
        }
        resp.extend_from_slice(&b[..n]);
    };
    let status = String::from_utf8_lossy(&resp[..end]).lines().next().unwrap_or_default().to_string();
    if status.split_whitespace().nth(1) != Some("101") {
        return Err(format!("ответ «{}»", status.trim()));
    }
    tcp.set_read_timeout(None).map_err(|e| e.to_string())?;
    Ok((tcp, conn, resp[end..].to_vec()))
}

/// Прочитать расшифрованные данные TLS (блокирующее чтение сокета).
fn tls_read(conn: &mut ClientConnection, tcp: &mut TcpStream, out: &mut [u8]) -> Result<usize, String> {
    loop {
        match conn.reader().read(out) {
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.to_string()),
        }
        let n = conn.read_tls(tcp).map_err(|e| e.to_string())?;
        if n == 0 {
            return Ok(0);
        }
        conn.process_new_packets().map_err(|e| e.to_string())?;
        while conn.wants_write() {
            conn.write_tls(tcp).map_err(|e| e.to_string())?;
        }
    }
}

/// Поток клиента: шифр «от клиента» (обфусцированный) или ничего (открытый транспорт).
enum Side {
    Obf(Ctr),
    Plain,
}
impl Side {
    fn apply(&mut self, b: &mut [u8]) {
        if let Side::Obf(c) = self {
            c.apply_keystream(b);
        }
    }
}

/// Соединение через WebSocket: начало, затем две нити — клиент → Telegram и Telegram → клиент.
#[allow(clippy::too_many_arguments)]
fn relay_ws(cfg: &Cfg, client: TcpStream, ip: Ipv4Addr, tag: [u8; 4], dc: i16, mut from_client: Side, mut to_client: Side, first: Vec<u8>) -> Result<(), String> {
    let (tcp, mut conn, rest) = ws_open(cfg, ip, dc)?;
    let (init, mut tg_enc, mut tg_dec) = relay_init(tag, dc, rand_fill);
    let mut wtcp = tcp.try_clone().map_err(|e| e.to_string())?;
    conn.writer().write_all(&ws_frame(2, &init, rand4())).map_err(|e| e.to_string())?;
    let mut split = Splitter::new(tag);
    let send = |conn: &mut ClientConnection, wtcp: &mut TcpStream, plain: &[u8], split: &mut Splitter, tg_enc: &mut Ctr| -> Result<(), String> {
        for mut p in split.push(plain) {
            tg_enc.apply_keystream(&mut p);
            conn.writer().write_all(&ws_frame(2, &p, rand4())).map_err(|e| e.to_string())?;
        }
        while conn.wants_write() {
            conn.write_tls(wtcp).map_err(|e| e.to_string())?;
        }
        Ok(())
    };
    send(&mut conn, &mut wtcp, &first, &mut split, &mut tg_enc)?;
    let conn = Arc::new(Mutex::new(conn));
    // клиент → Telegram
    let (c2, cw) = (client.try_clone().map_err(|e| e.to_string())?, Arc::clone(&conn));
    let up = std::thread::spawn(move || {
        let (mut c2, mut wtcp) = (c2, wtcp);
        let mut b = vec![0u8; 64 * 1024];
        loop {
            let n = match c2.read(&mut b) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            from_client.apply(&mut b[..n]);
            let mut g = match cw.lock() {
                Ok(g) => g,
                Err(_) => break,
            };
            if send(&mut g, &mut wtcp, &b[..n], &mut split, &mut tg_enc).is_err() {
                break;
            }
        }
        if let Ok(mut g) = cw.lock() {
            g.writer().write_all(&ws_frame(8, &[], rand4())).ok();
            g.send_close_notify();
            while g.wants_write() {
                if g.write_tls(&mut wtcp).is_err() {
                    break;
                }
            }
        }
        let _ = wtcp.shutdown(Shutdown::Both);
    });
    // Telegram → клиент
    let (mut rtcp, mut client) = (tcp, client);
    let mut buf = rest;
    let mut b = vec![0u8; 64 * 1024];
    let mut msg: Vec<u8> = Vec::new();
    'outer: loop {
        loop {
            match ws_parse(&buf) {
                Ok(Some((op, fin, data, used))) => {
                    buf.drain(..used);
                    match op {
                        0 | 2 => {
                            msg.extend_from_slice(&data);
                            if fin {
                                let mut m = std::mem::take(&mut msg);
                                tg_dec.apply_keystream(&mut m);
                                to_client.apply(&mut m);
                                if client.write_all(&m).is_err() {
                                    break 'outer;
                                }
                            }
                        }
                        8 => break 'outer,
                        9 => {
                            if let Ok(mut g) = conn.lock() {
                                g.writer().write_all(&ws_frame(10, &data, rand4())).ok();
                                while g.wants_write() {
                                    if g.write_tls(&mut rtcp).is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Ok(None) => break,
                Err(_) => break 'outer,
            }
        }
        // новые данные: сокет читается без блокировки шифра TLS, расшифровка — под ним
        let n = match rtcp.read(&mut b) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let Ok(mut g) = conn.lock() else { break };
        let mut src = &b[..n];
        while !src.is_empty() {
            if g.read_tls(&mut src).is_err() || g.process_new_packets().is_err() {
                break 'outer;
            }
        }
        let mut pb = [0u8; 16 * 1024];
        loop {
            match g.reader().read(&mut pb) {
                Ok(0) => break,
                Ok(k) => buf.extend_from_slice(&pb[..k]),
                Err(_) => break,
            }
        }
        while g.wants_write() {
            if g.write_tls(&mut rtcp).is_err() {
                break;
            }
        }
    }
    let _ = client.shutdown(Shutdown::Both);
    let _ = rtcp.shutdown(Shutdown::Both);
    let _ = up.join();
    Ok(())
}

fn handle(cfg: &Cfg, st: &Stats, mut client: TcpStream) -> Result<(), String> {
    let dst = original_dst(&client).ok_or("нет исходного адреса (SO_ORIGINAL_DST)")?;
    client.set_read_timeout(Some(HANDSHAKE_TIMEOUT)).map_err(|e| e.to_string())?;
    // начало потока: 4 байта отличают открытый транспорт, обфусцированный — 64 байта
    let mut head = Vec::with_capacity(64);
    let mut b = [0u8; 64];
    while head.len() < 4 {
        let n = client.read(&mut b[..4 - head.len()]).map_err(|e| e.to_string())?;
        if n == 0 {
            return Ok(());
        }
        head.extend_from_slice(&b[..n]);
    }
    let first4: [u8; 4] = head[..4].try_into().unwrap_or_default();
    // (тег, DC, от клиента, к клиенту, данные после начала)
    let plan: Option<([u8; 4], i16, Side, Side, Vec<u8>)> = if first4[0] == 0xef {
        dc_of_ip(*dst.ip()).map(|dc| (TAG_ABRIDGED, dc, Side::Plain, Side::Plain, head[1..].to_vec()))
    } else if first4 == TAG_INTERMEDIATE || first4 == TAG_PADDED {
        dc_of_ip(*dst.ip()).map(|dc| (first4, dc, Side::Plain, Side::Plain, Vec::new()))
    } else if first4[0] == 0x16 || [*b"GET ", *b"POST", *b"HEAD", *b"OPTI"].contains(&first4) {
        None
    } else {
        while head.len() < 64 {
            let n = client.read(&mut b[..64 - head.len()]).map_err(|e| e.to_string())?;
            if n == 0 {
                return Ok(());
            }
            head.extend_from_slice(&b[..n]);
        }
        let init: [u8; 64] = head[..64].try_into().unwrap_or([0; 64]);
        parse_obfuscated(&init).and_then(|o| {
            // DC из начала; 0 или неизвестный — по адресу (медиа — со знаком из начала)
            let known = |d: i16| matches!(d.unsigned_abs(), 1..=5 | 203);
            let dc = if known(o.dc) { o.dc } else { dc_of_ip(*dst.ip())? };
            Some((o.tag, dc, Side::Obf(o.dec), Side::Obf(o.enc), Vec::new()))
        })
    };
    client.set_read_timeout(None).map_err(|e| e.to_string())?;
    let ws_ip = plan.as_ref().and_then(|p| cfg.dcs.get(&p.1.abs()).copied().or_else(|| if p.1.unsigned_abs() == 203 { cfg.dcs.get(&2).copied() } else { None }));
    let cooling = plan.as_ref().is_some_and(|p| st.cooldown.lock().ok().and_then(|c| c.get(&p.1.abs()).copied()).is_some_and(|t| t > Instant::now()));
    if let (Some((tag, dc, from, to, rest)), Some(ip), false) = (plan, ws_ip, cooling) {
        st.ws.fetch_add(1, Ordering::Relaxed);
        // начало уже прочитано и расшифровано шифром клиента; оставшиеся байты — тоже через него
        let mut from = from;
        let mut rest = rest;
        from.apply(&mut rest);
        let c2 = client.try_clone().map_err(|e| e.to_string())?;
        match relay_ws(cfg, c2, ip, tag, dc, from, to, rest) {
            Ok(()) => return Ok(()),
            Err(e) => {
                st.ws_errors.fetch_add(1, Ordering::Relaxed);
                if let Ok(mut l) = st.last_error.lock() {
                    *l = format!("DC {}: {e}", dc.abs());
                }
                if let Ok(mut c) = st.cooldown.lock() {
                    c.insert(dc.abs(), Instant::now() + WS_COOLDOWN);
                }
                // WebSocket не открылся — то же соединение запасным путём (клиент ещё ничего не получил)
            }
        }
    }
    st.fallback.fetch_add(1, Ordering::Relaxed);
    fallback(cfg, client, dst, &head)
}

fn write_status(path: &str, listen: SocketAddr, st: &Stats) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let err = st.last_error.lock().map(|e| e.clone()).unwrap_or_default().replace(['"', '\\'], "'");
    let body = format!(
        "{{\"at\":{now},\"listen\":\"{listen}\",\"active\":{},\"ws\":{},\"fallback\":{},\"ws_errors\":{},\"last_error\":\"{err}\"}}\n",
        st.active.load(Ordering::Relaxed),
        st.ws.load(Ordering::Relaxed),
        st.fallback.load(Ordering::Relaxed),
        st.ws_errors.load(Ordering::Relaxed)
    );
    let tmp = format!("{path}.t");
    if std::fs::write(&tmp, body).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

/// Проверка входа WebSocket: первый запрос MTProto (req_pq_multi, без ключа) к DC и ответ resPQ.
fn probe(cfg: &Cfg, dc: i16) -> Result<Duration, String> {
    let ip = *cfg.dcs.get(&dc.abs()).ok_or_else(|| format!("для DC {dc} не задан адрес WebSocket (--dc)"))?;
    let t0 = Instant::now();
    let (mut tcp, mut conn, rest) = ws_open(cfg, ip, dc)?;
    let (init, mut enc, mut dec) = relay_init(TAG_ABRIDGED, dc, rand_fill);
    let mut nonce = [0u8; 16];
    rand_fill(&mut nonce);
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let mut msg = vec![0u8; 8];
    msg.extend_from_slice(&(now << 32).to_le_bytes());
    msg.extend_from_slice(&20u32.to_le_bytes());
    msg.extend_from_slice(&0xbe7e_8ef1u32.to_le_bytes());
    msg.extend_from_slice(&nonce);
    let mut pkt = vec![(msg.len() / 4) as u8];
    pkt.extend_from_slice(&msg);
    enc.apply_keystream(&mut pkt);
    conn.writer().write_all(&ws_frame(2, &init, rand4())).map_err(|e| e.to_string())?;
    conn.writer().write_all(&ws_frame(2, &pkt, rand4())).map_err(|e| e.to_string())?;
    while conn.wants_write() {
        conn.write_tls(&mut tcp).map_err(|e| e.to_string())?;
    }
    tcp.set_read_timeout(Some(HANDSHAKE_TIMEOUT)).map_err(|e| e.to_string())?;
    let mut buf = rest;
    let mut b = [0u8; 16 * 1024];
    loop {
        if let Some((op, _, mut data, used)) = ws_parse(&buf)? {
            buf.drain(..used);
            if op != 2 {
                continue;
            }
            dec.apply_keystream(&mut data);
            // abridged: байт длины, auth_key_id 0, msg_id, длина, конструктор resPQ 0x05162463
            return if data.len() > 25 && data[21..25] == 0x0516_2463u32.to_le_bytes() && data[25..41] == nonce {
                Ok(t0.elapsed())
            } else {
                Err("ответ DC не resPQ".into())
            };
        }
        let n = tls_read(&mut conn, &mut tcp, &mut b)?;
        if n == 0 {
            return Err("сервер закрыл соединение".into());
        }
        buf.extend_from_slice(&b[..n]);
    }
}

fn usage(m: &str) -> ! {
    eprintln!(
        "mi-tt-tgws: {m}\n  mi-tt-tgws --listen 0.0.0.0:18443 --dc 2:149.154.167.220 [--dc …] [--via-device mitt0] [--via-mark 0x4000] [--status file]\n  mi-tt-tgws --version"
    );
    std::process::exit(2)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--version") {
        println!("mi-tt-tgws {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    let (mut listen, mut dcs, mut via_device, mut via_mark, mut status, mut probe_dc) = (None, BTreeMap::new(), None, 0u32, None, None);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut v = || it.next().cloned().unwrap_or_else(|| usage(&format!("{a}: нет значения")));
        match a.as_str() {
            "--listen" => listen = Some(v().parse::<SocketAddr>().unwrap_or_else(|_| usage("--listen: адрес:порт"))),
            "--dc" => {
                let x = v();
                let (d, ip) = x.split_once(':').unwrap_or_else(|| usage("--dc: номер:IPv4"));
                dcs.insert(d.parse::<i16>().unwrap_or_else(|_| usage("--dc: номер DC")), ip.parse::<Ipv4Addr>().unwrap_or_else(|_| usage("--dc: IPv4")));
            }
            "--via-device" => via_device = Some(v()),
            "--via-mark" => {
                let x = v();
                via_mark = x.strip_prefix("0x").map_or_else(|| x.parse().ok(), |h| u32::from_str_radix(h, 16).ok()).unwrap_or_else(|| usage("--via-mark: число"));
            }
            "--status" => status = Some(v()),
            "--probe" => probe_dc = Some(v().parse::<i16>().unwrap_or_else(|_| usage("--probe: номер DC"))),
            _ => usage(&format!("неизвестный параметр {a}")),
        }
    }
    if dcs.is_empty() {
        // входы WebSocket по умолчанию: адреса kws<N>.web.telegram.org (DNS их может не отдавать — поэтому адресом;
        // имя — в SNI). Проверено ответом resPQ всех пяти DC (2026-11)
        for (dc, ip) in DEFAULT_DCS {
            dcs.insert(dc, ip);
        }
    }
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls = ClientConfig::builder_with_provider(Arc::new(rustls_rustcrypto::provider()))
        .with_safe_default_protocol_versions()
        .map(|b| b.with_root_certificates(roots).with_no_client_auth())
        .unwrap_or_else(|e| usage(&format!("TLS: {e}")));
    let cfg = Arc::new(Cfg { dcs, via_device, via_mark, tls: Arc::new(tls) });
    if let Some(dc) = probe_dc {
        match probe(&cfg, dc) {
            Ok(t) => {
                println!("{{\"ok\":true,\"dc\":{dc},\"ms\":{}}}", t.as_millis());
                return;
            }
            Err(e) => {
                println!("{{\"ok\":false,\"dc\":{dc},\"error\":\"{}\"}}", e.replace(['"', '\\'], "'"));
                std::process::exit(1);
            }
        }
    }
    let listen = listen.unwrap_or_else(|| usage("нужен --listen"));
    let st = Arc::new(Stats::default());
    let l = TcpListener::bind(listen).unwrap_or_else(|e| usage(&format!("{listen}: {e}")));
    if let Some(p) = status {
        let st = Arc::clone(&st);
        std::thread::spawn(move || {
            loop {
                write_status(&p, listen, &st);
                std::thread::sleep(Duration::from_secs(15));
            }
        });
    }
    for c in l.incoming() {
        let Ok(c) = c else { continue };
        let _ = c.set_nodelay(true);
        let (cfg, st) = (Arc::clone(&cfg), Arc::clone(&st));
        let _ = std::thread::Builder::new().stack_size(256 * 1024).spawn(move || {
            st.active.fetch_add(1, Ordering::Relaxed);
            if let Err(e) = handle(&cfg, &st, c) {
                if let Ok(mut l) = st.last_error.lock() {
                    *l = e;
                }
            }
            st.active.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_init_round_trip_through_relay() {
        // «клиент» строит начало так же, как прокси к Telegram: прокси разбирает его и видит тег и DC
        let mut seed = 7u8;
        let (init, _, _) = relay_init(TAG_PADDED, -4, |b| b.iter_mut().for_each(|x| {
            seed = seed.wrapping_mul(31).wrapping_add(17);
            *x = seed;
        }));
        let o = parse_obfuscated(&init).expect("MTProto");
        assert_eq!(o.tag, TAG_PADDED);
        assert_eq!(o.dc, -4);
        assert_ne!(init[0], 0xef);
    }

    #[test]
    fn stream_keys_match_both_ends() {
        // шифр «к Telegram» у прокси и «от клиента» у принимающей стороны — один поток
        let (init, mut enc, _) = relay_init(TAG_ABRIDGED, 2, rand_fill);
        let mut o = parse_obfuscated(&init).expect("MTProto");
        let mut msg = b"hello telegram".to_vec();
        enc.apply_keystream(&mut msg);
        o.dec.apply_keystream(&mut msg);
        assert_eq!(&msg, b"hello telegram");
        // и обратно: «к клиенту» у сервера = «от Telegram» у прокси
        let (init2, _, mut dec2) = relay_init(TAG_ABRIDGED, 2, rand_fill);
        let mut o2 = parse_obfuscated(&init2).expect("MTProto");
        let mut back = b"answer".to_vec();
        o2.enc.apply_keystream(&mut back);
        dec2.apply_keystream(&mut back);
        assert_eq!(&back, b"answer");
    }

    #[test]
    fn not_mtproto_is_rejected() {
        let mut tls = [0u8; 64];
        tls[..4].copy_from_slice(&[0x16, 0x03, 0x01, 0x02]);
        assert!(parse_obfuscated(&tls).is_none());
    }

    #[test]
    fn dc_by_address() {
        assert_eq!(dc_of_ip(Ipv4Addr::new(149, 154, 167, 51)), Some(2));
        assert_eq!(dc_of_ip(Ipv4Addr::new(149, 154, 167, 91)), Some(4));
        assert_eq!(dc_of_ip(Ipv4Addr::new(149, 154, 175, 100)), Some(3));
        assert_eq!(dc_of_ip(Ipv4Addr::new(149, 154, 175, 50)), Some(1));
        assert_eq!(dc_of_ip(Ipv4Addr::new(91, 108, 56, 130)), Some(5));
        assert_eq!(dc_of_ip(Ipv4Addr::new(8, 8, 8, 8)), None);
    }

    #[test]
    fn splitter_cuts_packets() {
        let mut s = Splitter::new(TAG_ABRIDGED);
        // пакет 8 байт (длина 2 слова) и начало следующего
        let out = s.push(&[2, 1, 2, 3, 4, 5, 6, 7, 8, 3, 9]);
        assert_eq!(out, vec![vec![2, 1, 2, 3, 4, 5, 6, 7, 8]]);
        let out = s.push(&[0; 11]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].len(), 13);
        let mut i = Splitter::new(TAG_INTERMEDIATE);
        let out = i.push(&[4, 0, 0, 0, 1, 2, 3, 4, 8, 0]);
        assert_eq!(out, vec![vec![4, 0, 0, 0, 1, 2, 3, 4]]);
    }

    #[test]
    fn ws_frames_round_trip() {
        let f = ws_frame(2, &[1, 2, 3], [9, 8, 7, 6]);
        let (op, fin, data, used) = ws_parse(&f).unwrap().unwrap();
        assert_eq!((op, fin, data, used), (2, true, vec![1, 2, 3], f.len()));
        let big = vec![5u8; 70_000];
        let f = ws_frame(2, &big, [1, 2, 3, 4]);
        assert_eq!(ws_parse(&f[..100]).unwrap(), None);
        assert_eq!(ws_parse(&f).unwrap().unwrap().2, big);
    }
}
