#![no_main]

#[macro_use]
extern crate libfuzzer_sys;

// netweir: encoder-stream instructions and field sections, in
// fuzzer-chosen chunks, against a decoder with a dynamic table.
fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    let mut d = quiche::h3::qpack::Decoder::with_max_table_capacity(
        u64::from(data[0]) * 64,
    );
    let max_size = if data[1] & 1 == 0 { u64::MAX } else { 4096 };
    let mut rest = &data[2..];

    while rest.len() >= 2 {
        let op = rest[0];
        let n = (rest[1] as usize).min(rest.len() - 2);
        let mut chunk = rest[2..2 + n].to_vec();
        rest = &rest[2 + n..];

        if op & 1 == 0 {
            if d.control(&mut chunk).is_err() {
                return;
            }
        } else {
            let blocked = d.is_blocked(&chunk);
            let before = d.insert_count();
            let r = d.decode_for_stream(&chunk, max_size, u64::from(op));
            if let (Ok(true), Ok(_)) = (&blocked, &r) {
                panic!("blocked section decoded");
            }
            assert_eq!(before, d.insert_count());
            let _ = d.take_instructions();
        }
    }
});
