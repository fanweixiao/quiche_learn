use colored::*;
use ring::rand::*;

const MAX_DATAGRAM_SIZE: usize = 1350;
const HTTP_REQ_STREAM_ID: u64 = 4;

fn main() {
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    // Setup the event loop.
    let poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    let bind_addr = "0.0.0.0:0";
    let peer_addr = "127.0.0.1:4433";

    println!("2/ bind_addr={}, peer_addr={}", bind_addr, peer_addr);

    // Create the UDP socket backing the QUIC connection, and register it with
    // the event loop.
    let socket = std::net::UdpSocket::bind(bind_addr).unwrap();
    socket.connect(peer_addr).unwrap();
    println!("3/ SOCKET_CONNECT peer_addr={}", peer_addr);

    let socket = mio::net::UdpSocket::from_socket(socket).unwrap();
    poll.register(
        &socket,
        mio::Token(0),
        mio::Ready::readable(),
        mio::PollOpt::edge(),
    )
    .unwrap();

    // Create the configuration for the QUIC connection.
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    // *CAUTION*: this should not be set to `false` in production!!!
    config.verify_peer(false);

    config
        .set_application_protos(b"\x05hq-29\x05hq-28\x05hq-27\x08http/0.9")
        .unwrap();

    config.set_max_idle_timeout(5000);
    config.set_max_udp_payload_size(MAX_DATAGRAM_SIZE as u64);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);

    // Generate a random source connection ID for the connection.
    let mut scid = [0xba; quiche::MAX_CONN_ID_LEN];
    SystemRandom::new().fill(&mut scid[..]).unwrap();
    println!("4/ generate scid={}", hex_dump(&scid));

    // Create a QUIC connection and initiate handshake.
    let mut conn = quiche::connect(Some(peer_addr), &scid, &mut config).unwrap();
    println!("5-1/ quiche::connect to={}", peer_addr);

    println!(
        "5-2/ connecting to {} from {} with scid {}",
        peer_addr,
        socket.local_addr().unwrap(),
        hex_dump(&scid)
    );

    let write = conn.send(&mut out).expect("initial send failed");
    println!("6/ CONN.SEND {} bytes", write);

    while let Err(e) = socket.send(&out[..write]) {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            println!("EE 6/ send() would block");
            continue;
        }

        panic!("EE-PANIC 6/ send() failed: {:?}", e);
    }

    println!(
        "7/ {} SOCKET.SEND written {} bytes={}",
        "HANDSHAKE".magenta(),
        write,
        hex_dump(&out[..write]).green()
    );

    let req_start = std::time::Instant::now();

    let mut req_sent = false;

    loop {
        println!("8/ [in loop]");
        poll.poll(&mut events, conn.timeout()).unwrap();

        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        'read: loop {
            // If the event loop reported no events, it means that the timeout
            // has expired, so handle it without attempting to read packets. We
            // will then proceed with the send loop.
            println!("9/ [in loop READ]");

            if events.is_empty() {
                println!(
                    "10-1/ events.is_empty(), timed out, set conn.on_timeout(), ----BREAK loop READ"
                );

                // CONNECTION CLOSE!!!!!!!!!!!
                // SHOULD: 等待有新的内容要发送
                conn.on_timeout();
                break 'read;
            }

            println!("10-2/ wait for SOCKET RECV");
            let len = match socket.recv(&mut buf) {
                Ok(v) => v,

                Err(e) => {
                    // There are no more UDP packets to read, so end the read
                    // loop.
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        println!("11-1/ recv() would block, ----BREAK loop READ");
                        break 'read;
                    }

                    panic!("EE-PANIC 11/ recv() failed: {:?}", e);
                }
            };

            println!(
                "12/ got {} bytes: {}",
                len,
                hex_dump(&mut buf[..len]).blue()
            );

            // Process potentially coalesced packets.
            let read = match conn.recv(&mut buf[..len]) {
                Ok(v) => v,

                Err(e) => {
                    eprintln!("EE 12/ recv failed: {:?}, ----CONT----", e);
                    continue 'read;
                }
            };

            println!("13/ processed {} bytes", read);
        }

        println!("14/ done reading loop READ");

        if conn.is_closed() {
            println!("15/ connection closed, {:?}", conn.stats());
            break;
        }

        println!(
            "16/ {}={}, req_sent={:?}",
            "conn.is_established()".magenta(),
            conn.is_established().to_string().magenta(),
            req_sent
        );

        // Send an HTTP request as soon as the connection is established.
        if conn.is_established() && !req_sent {
            // Send REQ
            println!("{}", "17/ SEND 1st REQ".red());

            let req = format!("REQ:PING");
            println!(
                "18/ CONN_SEND={}, HTTP_REQ_STREAM_ID={}",
                req.green(),
                HTTP_REQ_STREAM_ID
            );

            conn.stream_send(HTTP_REQ_STREAM_ID, req.as_bytes(), true)
                .unwrap();

            req_sent = true;
        }

        // Process all readable streams.
        println!("19-1/ >>START process all readable streams");
        for s in conn.readable() {
            println!("19-2/ for s={}", s);
            while let Ok((read, fin)) = conn.stream_recv(s, &mut buf) {
                let stream_buf = &buf[..read];
                println!(
                    "20/ received {} bytes={}",
                    read,
                    hex_dump(&buf[..read]).blue()
                );

                println!(
                    "21/ stream {} has {} bytes (fin? {})",
                    s,
                    stream_buf.len(),
                    fin
                );

                println!("22/ {}", unsafe {
                    std::str::from_utf8_unchecked(&stream_buf).red()
                });

                // The server reported that it has no more data to send, which
                // we got the full response. Close the connection.
                println!(
                    "23/ s={}, HTTP_REQ_STREAM_ID={}, fin={}",
                    s, HTTP_REQ_STREAM_ID, fin
                );
                if s == HTTP_REQ_STREAM_ID && fin {
                    println!(
                        "24/ response received in {:?}, closing...",
                        req_start.elapsed()
                    );

                    println!("25/ CONN.CLOSE()");
                    // SHOULD: DON'T CLOSE CONNECTION !!!!!!!!!!!
                    conn.close(true, 0x00, b"kthxbye").unwrap();
                }
            }
        }
        println!("19-2/ <<END process all readable streams");

        // Generate outgoing QUIC packets and send them on the UDP socket, until
        // quiche reports that there are no more packets to be sent.
        loop {
            println!("26-1/ >>>>>>START_OF_CONN_SEND loop");
            let write = match conn.send(&mut out) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    println!("26-2/ done writing");
                    break;
                }

                Err(e) => {
                    println!("26-3/ send failed: {:?}, CONN.CLOSE, ----BREAK CONN_SEND loop", e);

                    conn.close(false, 0x1, b"fail").ok();
                    break;
                }
            };

            println!(
                "26-4/ SOCKET_SEND {} bytes={}",
                write,
                hex_dump(&mut out[..write]).green()
            );
            if let Err(e) = socket.send(&out[..write]) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    println!("26-5/ send() would block");
                    break;
                }

                panic!("EE-PANIC 26-6/ send() failed: {:?}", e);
            }

            println!("26-7/ <<<<<<<<END_OF_CONN_SEND loop, written {}", write);
        }

        if conn.is_closed() {
            println!("27/ connection closed, {:?}", conn.stats());
            break;
        }
    }
}

fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter().map(|b| format!("{:02x}", b)).collect();

    vec.join("")
}
