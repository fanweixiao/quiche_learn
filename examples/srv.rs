use colored::*;

use std::net;
use std::str;

use std::collections::HashMap;

use ring::rand::*;

const MAX_DATAGRAM_SIZE: usize = 1350;

struct PartialResponse {
    body: Vec<u8>,

    written: usize,
}

struct Client {
    conn: std::pin::Pin<Box<quiche::Connection>>,

    partial_responses: HashMap<u64, PartialResponse>,
}

type ClientMap = HashMap<Vec<u8>, (net::SocketAddr, Client)>;

fn main() {
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    // let mut args = std::env::args();

    // let cmd = &args.next().unwrap();

    // if args.len() != 0 {
    //     println!("Usage: {}", cmd);
    //     println!("\nSee tools/apps/ for more complete implementations.");
    //     return;
    // }

    // Setup the event loop.
    let poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // Create the UDP listening socket, and register it with the event loop.
    let socket = net::UdpSocket::bind("127.0.0.1:4241").unwrap();
    //let socket = net::UdpSocket::bind("127.0.0.1:4433").unwrap();

    let socket = mio::net::UdpSocket::from_socket(socket).unwrap();
    poll.register(
        &socket,
        mio::Token(0),
        mio::Ready::readable(),
        mio::PollOpt::edge(),
    )
    .unwrap();

    // Create the configuration for the QUIC connections.
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();

    config.set_application_protos(b"\x05hq-29").unwrap();

    config.set_max_idle_timeout(5000);
    config.set_max_udp_payload_size(MAX_DATAGRAM_SIZE as u64);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);
    config.enable_early_data();

    let rng = SystemRandom::new();
    let conn_id_seed =
        ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

    let mut clients = ClientMap::new();

    println!(">> Start loop >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");

    loop {
        // Find the shorter timeout from all the active connections.
        //
        // TODO: use event loop that properly supports timers
        let timeout =
            clients.values().filter_map(|(_, c)| c.conn.timeout()).min();

        poll.poll(&mut events, timeout).unwrap();

        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        'read: loop {
            println!(">>[in loop] Start SOCKET_READ loop >>");
            // If the event loop reported no events, it means that the timeout
            // has expired, so handle it without attempting to read packets. We
            // will then proceed with the send loop.
            if events.is_empty() {
                println!(">>[in loop] timed out, SOCKET_READ loop BREAK <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<");

                clients.values_mut().for_each(|(_, c)| c.conn.on_timeout());

                break 'read;
            }

            println!(">>[in loop] SOCKET_RECV_FROM");
            let (len, src) = match socket.recv_from(&mut buf) {
                Ok(v) => v,

                Err(e) => {
                    // There are no more UDP packets to read, so end the read
                    // loop.
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        println!("[in loop] SOCKET_READ loop <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<");
                        break 'read;
                    }

                    eprintln!(">>[in loop] recv() failed: {:?}", e);
                    panic!(">>[in loop] recv() failed: {:?}", e);
                }
            };

            println!("1/ got {} bytes={}", len, hex_dump(&mut buf[..len]).blue());

            let pkt_buf = &mut buf[..len];

            // Parse the QUIC packet's header.
            let hdr = match quiche::Header::from_slice(
                pkt_buf,
                quiche::MAX_CONN_ID_LEN,
            ) {
                Ok(v) => v,

                Err(e) => {
                    println!("EE1~2/ Parsing packet header failed: {:?}", e);
                    continue 'read;
                }
            };

            println!("2-1/ got packet hdr={:?}", hdr);

            let conn_id = ring::hmac::sign(&conn_id_seed, &hdr.dcid);
            let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];

            println!(
                "2-2/ conn_id={}, looking if conn_id exist",
                hex_dump(&conn_id)
            );

            // Lookup a connection based on the packet's connection ID. If there
            // is no connection matching, create a new one.
            let (_, client) = if !clients.contains_key(&hdr.dcid)
                && !clients.contains_key(conn_id)
            {
                println!("3-1/ start create new connection");
                if hdr.ty != quiche::Type::Initial {
                    println!(
                        "EE| Packet is not Initial -------CONTINUE---------"
                    );
                    continue 'read;
                } else {
                    println!("3-2/ hdr.ty={:?}", hdr.ty);
                }

                println!("4/ hdr={:?}", hdr);
                if !quiche::version_is_supported(hdr.version) {
                    println!("==========Doing version negotiation");

                    let len =
                        quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out)
                            .unwrap();

                    let out = &out[..len];

                    if let Err(e) = socket.send_to(out, &src) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            println!("=========send() would block");
                            break;
                        }

                        panic!("=============send() failed: {:?}", e);
                    }
                    continue 'read;
                }

                let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                scid.copy_from_slice(&conn_id);
                println!("5/ scid={}", hex_dump(&scid));

                // Token is always present in Initial packets.
                let token = hdr.token.as_ref().unwrap();
                println!("6/ token={}", hex_dump(&token));

                // Do stateless retry if the client didn't send a token.
                if token.is_empty() {
                    println!("{}", "7-1/ token is_empty, START create new_token ===== Doing stateless retry".yellow());

                    let new_token = mint_token(&hdr, &src);
                    println!(
                        "7-2/ new_token={}, start quiche::retry",
                        hex_dump(&new_token)
                    );

                    let len = quiche::retry(
                        &hdr.scid,
                        &hdr.dcid,
                        &scid,
                        &new_token,
                        hdr.version,
                        &mut out,
                    )
                    .unwrap();

                    let out = &out[..len];
                    println!(
                        "7-3/ send new_token in retry?? SOCKET_SEND_TO out={}, src={}",
                        hex_dump(&out).green(),
                        src
                    );

                    if let Err(e) = socket.send_to(out, &src) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            println!("send() would block");
                            break;
                        }

                        panic!("send() failed: {:?}", e);
                    }
                    println!("7-4/ SOCKET_SEND_TO(DONE), ----CONT----");
                    continue 'read;
                } else {
                    println!("{}", "77777/ token is not empty".yellow());
                }

                let odcid = validate_token(&src, token);
                println!("7-5/ odcid={}", hex_dump(&odcid.unwrap()));

                // The token was not valid, meaning the retry failed, so
                // drop the packet.
                if odcid == None {
                    println!(
                        "EE-7| Invalid address validation token, ----CONT----"
                    );
                    continue 'read;
                }

                println!(
                    "8/ scid={}, hdr.dcid={}",
                    hex_dump(&scid),
                    hex_dump(&hdr.dcid)
                );

                if scid.len() != hdr.dcid.len() {
                    println!(
                        "EE-8| Invalid destination connection ID, ----CONT----"
                    );
                    continue 'read;
                }

                // Reuse the source connection ID we sent in the Retry
                // packet, instead of changing it again.
                println!(
                    "9-1/ START REUSE scid: COPY hdr.dcid={} TO scid={}",
                    hex_dump(&hdr.dcid),
                    hex_dump(&scid)
                );
                scid.copy_from_slice(&hdr.dcid);
                println!(
                    "9-2/ REUSE(DONE) scid: hdr.dcid={}, scid={}",
                    hex_dump(&hdr.dcid),
                    hex_dump(&scid)
                );

                println!(
                    "10/ New connection: hdr.dcid={} scid={}",
                    hex_dump(&hdr.dcid),
                    hex_dump(&scid)
                );

                println!(
                    "11/ Create Quiche Conn: scid={}, odcid={}, hdr.dcid={}",
                    hex_dump(&scid),
                    hex_dump(&odcid.unwrap()),
                    hex_dump(&hdr.dcid)
                );
                let conn = quiche::accept(&scid, odcid, &mut config).unwrap();

                println!("12/ Create Quiche client");
                let client = Client {
                    conn,
                    partial_responses: HashMap::new(),
                };

                clients.insert(scid.to_vec(), (src, client));

                clients.get_mut(&scid[..]).unwrap()
            } else {
                println!(
                    "3-*******3*********/ existed connection by hdr.dcid={}, conn_id={}",
                    hex_dump(&hdr.dcid),
                    hex_dump(&conn_id)
                );
                match clients.get_mut(&hdr.dcid) {
                    Some(v) => v,

                    None => clients.get_mut(conn_id).unwrap(),
                }
            };

            // Process potentially coalesced packets.
            let read = match client.conn.recv(pkt_buf) {
                Ok(v) => v,

                Err(e) => {
                    println!(
                        "EE-13| {} recv failed: {:?}",
                        client.conn.trace_id(),
                        e
                    );
                    continue 'read;
                }
            };

            println!(
                "13/ Process potentially coalesced packets: conn.trace_id={} processed {} bytes={}",
                client.conn.trace_id(),
                read,
                hex_dump(&mut pkt_buf[..read]).blue()
            );

            println!(
                "14-1/ client.conn.is_established={:?}",
                client.conn.is_established()
            );

            println!(
                "14-2/ client.conn.is_in_early_data={:?}",
                client.conn.is_in_early_data()
            );

            if client.conn.is_in_early_data() || client.conn.is_established() {
                println!("14-3/ GOT! sclient.conn.is_in_early_data() || client.conn.is_established()");
                // Handle writable streams.
                for stream_id in client.conn.writable() {
                    handle_writable(client, stream_id);
                }

                // Process all readable streams.
                for s in client.conn.readable() {
                    while let Ok((read, fin)) =
                        client.conn.stream_recv(s, &mut buf)
                    {
                        println!(
                            "16-1/ {} received {} bytes",
                            client.conn.trace_id(),
                            read
                        );

                        let stream_buf = &buf[..read];

                        println!(
                            "16-2/ {} stream {} has {} bytes (fin? {})",
                            client.conn.trace_id(),
                            s,
                            stream_buf.len(),
                            fin
                        );

                        handle_stream(client, s, stream_buf);
                    }
                }
            }

            println!("15/ READ_LOOP_RESTART (DONE)");
        }

        println!("17/ READ_LOOP (OVER) ______");

        // Generate outgoing QUIC packets for all active connections and send
        // them on the UDP socket, until quiche reports that there are no more
        // packets to be sent.
        for (peer, client) in clients.values_mut() {
            loop {
                let write = match client.conn.send(&mut out) {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => {
                        println!(
                            "EE 18-1/ {} done writing",
                            client.conn.trace_id()
                        );
                        break;
                    }

                    Err(e) => {
                        println!(
                            "EE 18-2/ {} send failed: {:?}",
                            client.conn.trace_id(),
                            e
                        );

                        client.conn.close(false, 0x1, b"fail").ok();
                        break;
                    }
                };

                // TODO: coalesce packets.
                if let Err(e) = socket.send_to(&out[..write], &peer) {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        println!("EE 19-1/ send() would block");
                        break;
                    }

                    panic!("EE 19-2/ send() failed: {:?}", e);
                }

                println!(
                    "19/ {} written {} bytes={}",
                    client.conn.trace_id(),
                    write,
                    hex_dump(&out[..write]).green()
                );
            }
        }

        // Garbage collect closed connections.
        clients.retain(|_, (_, ref mut c)| {
            println!("20-1/ Collecting garbage");

            if c.conn.is_closed() {
                println!(
                    "20-2/{} connection collected {:?}",
                    c.conn.trace_id(),
                    c.conn.stats()
                );
            }

            !c.conn.is_closed()
        });
    }
}

/// Generate a stateless retry token.
///
/// The token includes the static string `"quiche"` followed by the IP address
/// of the client and by the original destination connection ID generated by the
/// client.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
fn mint_token(hdr: &quiche::Header, src: &net::SocketAddr) -> Vec<u8> {
    let mut token = Vec::new();

    token.extend_from_slice(b"quiche");

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    token.extend_from_slice(&addr);
    token.extend_from_slice(&hdr.dcid);

    token
}

/// Validates a stateless retry token.
///
/// This checks that the ticket includes the `"quiche"` static string, and that
/// the client IP address matches the address stored in the ticket.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
fn validate_token<'a>(
    src: &net::SocketAddr, token: &'a [u8],
) -> Option<&'a [u8]> {
    if token.len() < 6 {
        return None;
    }

    if &token[..6] != b"quiche" {
        return None;
    }

    let token = &token[6..];

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    if token.len() < addr.len() || &token[..addr.len()] != addr.as_slice() {
        return None;
    }

    let token = &token[addr.len()..];

    Some(&token[..])
}

/// Handles incoming HTTP/0.9 requests.
fn handle_stream(client: &mut Client, stream_id: u64, buf: &[u8]) {
    let conn = &mut client.conn;

    // REQ
    println!(
        "{} got {} bytes: {}",
        "16**1/ HANDLE_STREAM ".red(),
        buf.len(),
        str::from_utf8(buf).unwrap().red()
    );

    // RESP
    let body = b"RESP:PONG CELLA".to_vec();

    let written = match conn.stream_send(stream_id, &body, true) {
        Ok(v) => v,

        Err(quiche::Error::Done) => 0,

        Err(e) => {
            println!("EE| {} stream send failed {:?}", conn.trace_id(), e);
            return;
        }
    };

    println!(
        "16**2/ written={}, body.len()={}, body={:?}",
        written,
        body.len(),
        hex_dump(&body)
    );
    println!("{}", "16**3/ RESP DONE".red());

    if written < body.len() {
        let response = PartialResponse { body, written };
        client.partial_responses.insert(stream_id, response);
    }
}

/// Handles newly writable streams.
fn handle_writable(client: &mut Client, stream_id: u64) {
    let conn = &mut client.conn;

    println!(
        ">>>>>>>>>>>>>>14-4/ {} stream {} is writable",
        conn.trace_id(),
        stream_id
    );

    if !client.partial_responses.contains_key(&stream_id) {
        return;
    }

    let resp = client.partial_responses.get_mut(&stream_id).unwrap();
    let body = &resp.body[resp.written..];

    println!(
        ">>>>>>>>>>>>>>14-5/ CONN.STREAM_SEND body={}",
        hex_dump(&body).green()
    );
    let written = match conn.stream_send(stream_id, &body, true) {
        Ok(v) => v,

        Err(quiche::Error::Done) => 0,

        Err(e) => {
            println!("EE| {} stream send failed {:?}", conn.trace_id(), e);
            return;
        }
    };

    resp.written += written;

    if resp.written == resp.body.len() {
        client.partial_responses.remove(&stream_id);
    }
}

fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter().map(|b| format!("{:02x}", b)).collect();

    vec.join("")
}
