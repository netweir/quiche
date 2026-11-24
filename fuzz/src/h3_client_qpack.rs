#![no_main]

#[macro_use]
extern crate libfuzzer_sys;

use std::collections::HashMap;

use quiche::h3::testing::Session;
use quiche::h3::Event;

// netweir: an HTTP/3 client with a dynamic table, fed fuzzer-chosen bytes
// on the server's encoder stream and on two response streams, with resets
// from either side in between. No stream may report anything after its
// Finished or Reset, and no stream may report Data before its Headers: a
// DATA frame before any HEADERS closes the connection, as Chromium does.
fuzz_target!(|data: &[u8]| {
    let (mut config, mut h3_config) = Session::default_configs().unwrap();
    h3_config.set_qpack_max_table_capacity(4096);
    h3_config.set_qpack_blocked_streams(4);
    h3_config.enable_chromium(true);
    let mut s = Session::with_configs(&mut config, &h3_config).unwrap();
    s.handshake().unwrap();

    let streams = [
        s.send_request(true).unwrap().0,
        s.send_request(true).unwrap().0,
    ];
    while s.poll_server().is_ok() {}

    // The server's encoder stream follows its control stream.
    const ENCODER: u64 = 7;

    // Per stream: whether it ended, and whether its Headers came.
    let mut ended: HashMap<u64, bool> = HashMap::new();
    let mut headers: HashMap<u64, bool> = HashMap::new();

    let mut rest = data;
    while rest.len() >= 2 {
        let op = rest[0];
        let n = (rest[1] as usize).min(rest.len() - 2);
        let chunk = &rest[2..2 + n];
        rest = &rest[2 + n..];

        let stream = streams[usize::from(op >> 2 & 1)];
        match op & 3 {
            0 => {
                s.pipe.server.stream_send(ENCODER, chunk, false).ok();
            },
            1 => {
                s.pipe.server.stream_send(stream, chunk, op & 0x80 != 0).ok();
            },
            2 => {
                s.pipe
                    .server
                    .stream_shutdown(stream, quiche::Shutdown::Write, 42)
                    .ok();
            },
            _ => {
                s.pipe
                    .client
                    .stream_shutdown(stream, quiche::Shutdown::Read, 0)
                    .ok();
            },
        }
        s.advance().ok();

        loop {
            let (id, ev) = match s.poll_client() {
                Ok(v) => v,
                Err(quiche::h3::Error::Done) => break,
                Err(_) => return,
            };
            let ended = ended.entry(id).or_default();
            assert!(!*ended, "{:?} on stream {} after it ended", ev, id);
            match ev {
                Event::Headers { .. } => {
                    headers.insert(id, true);
                },
                Event::Data => {
                    assert!(
                        headers.get(&id).copied().unwrap_or(false),
                        "Data on stream {} before its Headers",
                        id
                    );
                    let mut b = [0; 1024];
                    let (client, conn) = (&mut s.client, &mut s.pipe.client);
                    while client.recv_body(conn, id, &mut b).is_ok() {}
                },
                Event::Finished | Event::Reset(_) => *ended = true,
                _ => (),
            }
        }
    }
});
