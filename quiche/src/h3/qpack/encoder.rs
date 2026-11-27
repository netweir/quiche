// Copyright (C) 2019, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;

use super::Error;
use super::Result;

use crate::h3::NameValue;

use super::INDEXED;
use super::INDEXED_WITH_POST_BASE;
use super::LITERAL;
use super::LITERAL_WITH_NAME_REF;

/// netweir: how an encoder uses the peer's dynamic table.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    /// The static table and literals only, as upstream quiche encodes.
    #[default]
    Static,

    /// As Chromium's QUIC encodes: QUICHE's `QpackEncoder`
    /// (quiche/quic/core/qpack/qpack_encoder.cc, `FirstPassEncode` and
    /// `SecondPassEncode`), Huffman only where it's shorter
    /// (qpack_instruction_encoder.cc).
    Chromium,

    /// As Safari 27.2 was recorded encoding against a server that offered
    /// a table (profiles/safari-27-macos.h3-qpack.capture.json): a field
    /// goes in the table the second time it's sent once the table can be
    /// used, under its name in the static table, else in the dynamic one,
    /// else a literal name; the section that inserts refers to the new
    /// entry past its Base, later ones from below it. With no stream
    /// allowed to block, it still inserts but refers only to entries the
    /// peer has acknowledged, and leaves out an insert that would name a
    /// dynamic entry.
    Safari,
}

/// netweir: how large Safari 27.2 let a server's table grow: 65536 bytes
/// when the server offered 1 MiB, whatever its own
/// SETTINGS_QPACK_MAX_TABLE_CAPACITY (16383).
pub const SAFARI_MAX_TABLE_CAPACITY: u64 = 65536;

/// A QPACK encoder.
#[derive(Default)]
pub struct Encoder {
    mode: Mode,

    /// netweir: the most this encoder lets the peer's table grow to, its
    /// own SETTINGS_QPACK_MAX_TABLE_CAPACITY in Chromium
    /// (quic_spdy_session.cc, OnSetting: `std::min(value,
    /// qpack_maximum_dynamic_table_capacity_)`).
    local_max_capacity: u64,

    table: Table,

    blocking: Blocking,

    /// The peer's SETTINGS_QPACK_BLOCKED_STREAMS.
    max_blocked_streams: u64,

    /// Instructions for the encoder stream, not sent yet.
    instructions: Vec<u8>,

    /// The start of a decoder stream instruction not all here yet.
    decoder_in: Vec<u8>,

    /// Safari: the fields sent once the table could be used.
    sent: HashSet<(Vec<u8>, Vec<u8>)>,
}

impl Encoder {
    /// Creates a new QPACK encoder.
    pub fn new() -> Encoder {
        Encoder::default()
    }

    /// netweir: an encoder in `mode`, which lets the peer's dynamic table
    /// grow to `local_max_capacity` at most.
    pub fn with_mode(mode: Mode, local_max_capacity: u64) -> Encoder {
        Encoder {
            mode,
            local_max_capacity,
            ..Encoder::default()
        }
    }

    /// netweir: the peer's SETTINGS_QPACK_MAX_TABLE_CAPACITY and
    /// SETTINGS_QPACK_BLOCKED_STREAMS, as far as it sent them. A capacity
    /// sets the table's, capped at this encoder's own, and queues a Set
    /// Dynamic Table Capacity instruction that goes out with the next
    /// field section's (quic_spdy_session.cc, OnSetting;
    /// qpack_encoder.cc, SetDynamicTableCapacity).
    pub fn on_peer_settings(
        &mut self, max_table_capacity: Option<u64>, blocked_streams: Option<u64>,
    ) {
        if self.mode == Mode::Static {
            return;
        }

        if let Some(max) = max_table_capacity {
            self.table.max_capacity = max;
            let capacity = max.min(self.local_max_capacity);
            encode_int_vec(capacity, 0x20, 5, &mut self.instructions);
            self.table.set_capacity(capacity);
        }

        if let Some(blocked) = blocked_streams {
            self.max_blocked_streams = blocked;
        }
    }

    /// netweir: takes the encoder stream instructions to send.
    pub fn take_instructions(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.instructions)
    }

    /// netweir: reads instructions from the peer's decoder stream (RFC
    /// 9204, Section 4.4), keeping a partial one for the next call
    /// (qpack_encoder.cc, OnInsertCountIncrement, OnHeaderAcknowledgement,
    /// OnStreamCancellation). An encoder in `Mode::Static` ignores them, as
    /// upstream quiche does.
    pub fn on_decoder_stream(&mut self, data: &[u8]) -> Result<()> {
        if self.mode == Mode::Static {
            return Ok(());
        }

        self.decoder_in.extend_from_slice(data);

        let buf = std::mem::take(&mut self.decoder_in);
        let mut b = octets::Octets::with_slice(&buf);

        while b.cap() > 0 {
            let start = b.off();
            let first = b.peek_u8()?;

            let instruction = if first & 0x80 != 0 {
                super::decoder::decode_int(&mut b, 7).map(|id| (0, id))
            } else if first & 0x40 != 0 {
                super::decoder::decode_int(&mut b, 6).map(|id| (1, id))
            } else {
                super::decoder::decode_int(&mut b, 6).map(|n| (2, n))
            };

            match instruction {
                Ok((0, stream_id)) =>
                    if !self.blocking.on_header_acknowledgement(stream_id) {
                        return Err(Error::DecoderStream);
                    },

                Ok((1, stream_id)) =>
                    self.blocking.on_stream_cancellation(stream_id),

                Ok((_, increment)) => {
                    if increment == 0 {
                        return Err(Error::DecoderStream);
                    }

                    self.blocking.known_received_count = self
                        .blocking
                        .known_received_count
                        .checked_add(increment)
                        .ok_or(Error::DecoderStream)?;

                    if self.blocking.known_received_count > self.table.inserted()
                    {
                        return Err(Error::DecoderStream);
                    }
                },

                Err(Error::BufferTooShort) => {
                    self.decoder_in = buf[start..].to_vec();
                    return Ok(());
                },

                Err(_) => return Err(Error::DecoderStream),
            }
        }

        Ok(())
    }

    /// Encodes a list of headers into a QPACK header block.
    pub fn encode<T: NameValue>(
        &mut self, headers: &[T], out: &mut [u8],
    ) -> Result<usize> {
        let mut b = octets::OctetsMut::with_slice(out);

        // Required Insert Count.
        encode_int(0, 0, 8, &mut b)?;

        // Base.
        encode_int(0, 0, 7, &mut b)?;

        for h in headers {
            match lookup_static(h) {
                Some((idx, true)) => {
                    const STATIC: u8 = 0x40;

                    // Encode as statically indexed.
                    encode_int(idx, INDEXED | STATIC, 6, &mut b)?;
                },

                Some((idx, false)) => {
                    const STATIC: u8 = 0x10;

                    // Encode value as literal with static name reference.
                    encode_int(idx, LITERAL_WITH_NAME_REF | STATIC, 4, &mut b)?;
                    encode_str::<false>(h.value(), 0, 7, &mut b)?;
                },

                None => {
                    // Encode as fully literal.

                    encode_str::<true>(h.name(), LITERAL, 3, &mut b)?;
                    encode_str::<false>(h.value(), 0, 7, &mut b)?;
                },
            };
        }

        Ok(b.off())
    }

    /// netweir: encodes the field section of request stream `stream_id`,
    /// as `encode` does for an encoder in `Mode::Static`; in another mode
    /// it may insert into the peer's dynamic table and refer to it,
    /// queueing the inserts for the encoder stream.
    pub fn encode_for_stream<T: NameValue>(
        &mut self, stream_id: u64, headers: &[T], out: &mut [u8],
    ) -> Result<usize> {
        let inserted_before = self.table.inserted();

        let representations = match self.mode {
            Mode::Static => return self.encode(headers, out),
            Mode::Chromium => self.first_pass_chromium(stream_id, headers),
            Mode::Safari => self.first_pass_safari(stream_id, headers),
        };

        let referred: Vec<u64> = representations
            .iter()
            .filter_map(Representation::dynamic_index)
            .collect();

        let required_insert_count =
            referred.iter().max().map_or(0, |&max| max + 1);

        if !referred.is_empty() {
            self.blocking.on_header_block_sent(
                stream_id,
                referred,
                required_insert_count,
            );
        }

        // Chromium refers to entries from the Required Insert Count down,
        // never past it (qpack_encoder.cc, SecondPassEncode); Safari's Base
        // is the insert count before the section's own inserts.
        let base = match self.mode {
            Mode::Safari => inserted_before,
            _ => required_insert_count,
        };

        let block =
            self.second_pass(&representations, required_insert_count, base);

        let out = out.get_mut(..block.len()).ok_or(Error::BufferTooShort)?;
        out.copy_from_slice(&block);

        Ok(block.len())
    }

    /// QUICHE's `QpackEncoder::FirstPassEncode`: each field as a reference
    /// to an existing entry, a new entry inserted and referred to, an
    /// entry's name with a literal value, or literals; the inserts queued
    /// for the encoder stream. Dynamic indices are absolute.
    fn first_pass_chromium<T: NameValue>(
        &mut self, stream_id: u64, headers: &[T],
    ) -> Vec<Representation> {
        let mut representations = Vec::with_capacity(headers.len());

        let known_received_count = self.blocking.known_received_count;

        // Blocking entries, and unacknowledged ones, must not be evicted.
        let mut smallest_non_evictable_index = self
            .blocking
            .smallest_blocking_index()
            .min(known_received_count);

        let draining_index = self.table.draining_index(DRAINING_FRACTION);

        let blocking_allowed = self
            .blocking
            .blocking_allowed_on_stream(stream_id, self.max_blocked_streams);

        for (name, value) in split_values(headers) {
            let name = &name[..];
            let value = &value[..];

            let size = entry_size(name, value);

            let mut found = self.table.find(name, value);

            if let Match::NameAndValue { is_static, index } = found {
                if is_static {
                    representations.push(Representation::Indexed {
                        is_static: true,
                        index,
                    });
                    continue;
                }

                if index >= draining_index {
                    if blocking_allowed || index < known_received_count {
                        representations.push(Representation::Indexed {
                            is_static: false,
                            index,
                        });
                        smallest_non_evictable_index =
                            smallest_non_evictable_index.min(index);
                        continue;
                    }
                } else if blocking_allowed &&
                    size <= self.table.max_insert_size_without_evicting(
                        smallest_non_evictable_index.min(index),
                    )
                {
                    // A draining entry is duplicated rather than referred to.
                    let relative = self.table.inserted() - index - 1;
                    encode_int_vec(relative, 0x00, 5, &mut self.instructions);
                    let new_index = self.table.insert(name, value);
                    representations.push(Representation::Indexed {
                        is_static: false,
                        index: new_index,
                    });
                    smallest_non_evictable_index =
                        smallest_non_evictable_index.min(index);
                    continue;
                }

                // The match can't be used: try its name alone, unless that's
                // the same entry.
                match self.table.find_name(name) {
                    Match::Name {
                        is_static: s,
                        index: i,
                    } if !(s == is_static && i == index) =>
                        found = Match::Name {
                            is_static: s,
                            index: i,
                        },

                    _ => {
                        representations.push(Representation::Literal {
                            name: name.to_vec(),
                            value: value.to_vec(),
                        });
                        continue;
                    },
                }
            }

            match found {
                Match::Name {
                    is_static: true,
                    index,
                } => {
                    if blocking_allowed &&
                        size <= self.table.max_insert_size_without_evicting(
                            smallest_non_evictable_index,
                        )
                    {
                        self.insert_with_name_reference(true, index, value);
                        let new_index = self.table.insert(name, value);
                        representations.push(Representation::Indexed {
                            is_static: false,
                            index: new_index,
                        });
                        smallest_non_evictable_index =
                            smallest_non_evictable_index.min(new_index);
                        continue;
                    }

                    representations.push(Representation::NameReference {
                        is_static: true,
                        index,
                        value: value.to_vec(),
                    });
                },

                Match::Name {
                    is_static: false,
                    index,
                } => {
                    if blocking_allowed &&
                        size <= self.table.max_insert_size_without_evicting(
                            smallest_non_evictable_index.min(index),
                        )
                    {
                        let relative = self.table.inserted() - index - 1;
                        self.insert_with_name_reference(false, relative, value);
                        let new_index = self.table.insert(name, value);
                        representations.push(Representation::Indexed {
                            is_static: false,
                            index: new_index,
                        });
                        smallest_non_evictable_index =
                            smallest_non_evictable_index.min(index);
                        continue;
                    }

                    if (blocking_allowed || index < known_received_count) &&
                        index >= draining_index
                    {
                        representations.push(Representation::NameReference {
                            is_static: false,
                            index,
                            value: value.to_vec(),
                        });
                        smallest_non_evictable_index =
                            smallest_non_evictable_index.min(index);
                        continue;
                    }

                    representations.push(Representation::Literal {
                        name: name.to_vec(),
                        value: value.to_vec(),
                    });
                },

                _ => {
                    if blocking_allowed &&
                        size <= self.table.max_insert_size_without_evicting(
                            smallest_non_evictable_index,
                        )
                    {
                        // Insert With Literal Name.
                        encode_string_vec(
                            name,
                            0x40,
                            5,
                            true,
                            self.huffman_strict(),
                            &mut self.instructions,
                        );
                        encode_string_vec(
                            value,
                            0x00,
                            7,
                            false,
                            self.huffman_strict(),
                            &mut self.instructions,
                        );
                        let new_index = self.table.insert(name, value);
                        representations.push(Representation::Indexed {
                            is_static: false,
                            index: new_index,
                        });
                        smallest_non_evictable_index =
                            smallest_non_evictable_index.min(new_index);
                        continue;
                    }

                    representations.push(Representation::Literal {
                        name: name.to_vec(),
                        value: value.to_vec(),
                    });
                },
            }
        }

        representations
    }

    /// Safari's first pass (see `Mode::Safari`). Dynamic indices are
    /// absolute.
    fn first_pass_safari<T: NameValue>(
        &mut self, stream_id: u64, headers: &[T],
    ) -> Vec<Representation> {
        let mut representations = Vec::with_capacity(headers.len());

        let usable = self.table.capacity > 0;
        let known_received_count = self.blocking.known_received_count;
        let blocking_allowed = self
            .blocking
            .blocking_allowed_on_stream(stream_id, self.max_blocked_streams);
        let referable =
            |index: u64| blocking_allowed || index < known_received_count;

        // Entries an unacknowledged section needs, or the peer may not
        // have yet, aren't evicted.
        // shortcut: Safari's eviction wasn't recorded (no table filled);
        // this is QUICHE's rule, until a recording fills one.
        let mut smallest_non_evictable_index = self
            .blocking
            .smallest_blocking_index()
            .min(known_received_count);

        for (name, value) in split_values(headers) {
            let found = self.table.find(&name, &value);

            match found {
                Match::NameAndValue {
                    is_static: true,
                    index,
                } => {
                    representations.push(Representation::Indexed {
                        is_static: true,
                        index,
                    });
                    continue;
                },

                Match::NameAndValue {
                    is_static: false,
                    index,
                } if referable(index) => {
                    representations.push(Representation::Indexed {
                        is_static: false,
                        index,
                    });
                    smallest_non_evictable_index =
                        smallest_non_evictable_index.min(index);
                    continue;
                },

                _ => (),
            }

            let in_table = matches!(found, Match::NameAndValue { .. });
            let again =
                usable && !self.sent.insert((name.clone(), value.clone()));
            let by_name = self.table.find_name(&name);

            if again && !in_table {
                let size = entry_size(&name, &value);

                let inserted = match by_name {
                    Match::Name {
                        is_static: true,
                        index,
                    } if size <=
                        self.table.max_insert_size_without_evicting(
                            smallest_non_evictable_index,
                        ) =>
                    {
                        self.insert_with_name_reference(true, index, &value);
                        true
                    },

                    Match::Name {
                        is_static: false,
                        index,
                    } if blocking_allowed &&
                        size <= self
                            .table
                            .max_insert_size_without_evicting(
                                smallest_non_evictable_index.min(index),
                            ) =>
                    {
                        let relative = self.table.inserted() - index - 1;
                        self.insert_with_name_reference(false, relative, &value);
                        true
                    },

                    Match::None
                        if size <=
                            self.table.max_insert_size_without_evicting(
                                smallest_non_evictable_index,
                            ) =>
                    {
                        // Insert With Literal Name.
                        encode_string_vec(
                            &name,
                            0x40,
                            5,
                            true,
                            self.huffman_strict(),
                            &mut self.instructions,
                        );
                        encode_string_vec(
                            &value,
                            0x00,
                            7,
                            false,
                            self.huffman_strict(),
                            &mut self.instructions,
                        );
                        true
                    },

                    _ => false,
                };

                if inserted {
                    let new_index = self.table.insert(&name, &value);

                    if blocking_allowed {
                        representations.push(Representation::Indexed {
                            is_static: false,
                            index: new_index,
                        });
                        smallest_non_evictable_index =
                            smallest_non_evictable_index.min(new_index);
                        continue;
                    }
                }
            }

            // As the field is sent the first time: its name from a table,
            // else literals.
            match self.table.find_name(&name) {
                Match::Name {
                    is_static: true,
                    index,
                } => representations.push(Representation::NameReference {
                    is_static: true,
                    index,
                    value,
                }),

                Match::Name {
                    is_static: false,
                    index,
                } if referable(index) => {
                    representations.push(Representation::NameReference {
                        is_static: false,
                        index,
                        value,
                    });
                    smallest_non_evictable_index =
                        smallest_non_evictable_index.min(index);
                },

                _ =>
                    representations.push(Representation::Literal { name, value }),
            }
        }

        representations
    }

    fn insert_with_name_reference(
        &mut self, is_static: bool, index: u64, value: &[u8],
    ) {
        let first = if is_static { 0xc0 } else { 0x80 };
        encode_int_vec(index, first, 6, &mut self.instructions);
        encode_string_vec(
            value,
            0x00,
            7,
            false,
            self.huffman_strict(),
            &mut self.instructions,
        );
    }

    /// Whether a string is Huffman-coded only when that's shorter, as
    /// QUICHE's `QpackInstructionEncoder` does, rather than when it's no
    /// longer, as upstream quiche does.
    fn huffman_strict(&self) -> bool {
        self.mode == Mode::Chromium
    }

    /// QUICHE's `QpackEncoder::SecondPassEncode`: the prefix, then each
    /// representation, dynamic indices made relative to `base`.
    fn second_pass(
        &self, representations: &[Representation], required_insert_count: u64,
        base: u64,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        let strict = self.huffman_strict();

        let encoded_insert_count = if required_insert_count == 0 {
            0
        } else {
            required_insert_count % (2 * self.table.max_entries()) + 1
        };
        encode_int_vec(encoded_insert_count, 0, 8, &mut out);

        if base >= required_insert_count {
            encode_int_vec(base - required_insert_count, 0, 7, &mut out);
        } else {
            encode_int_vec(required_insert_count - base - 1, 0x80, 7, &mut out);
        }

        for r in representations {
            match r {
                Representation::Indexed {
                    is_static: true,
                    index,
                } => encode_int_vec(*index, INDEXED | 0x40, 6, &mut out),

                Representation::Indexed {
                    is_static: false,
                    index,
                } if *index < base =>
                    encode_int_vec(base - index - 1, INDEXED, 6, &mut out),

                Representation::Indexed { index, .. } => encode_int_vec(
                    index - base,
                    INDEXED_WITH_POST_BASE,
                    4,
                    &mut out,
                ),

                Representation::NameReference {
                    is_static,
                    index,
                    value,
                } => {
                    if *is_static {
                        encode_int_vec(
                            *index,
                            LITERAL_WITH_NAME_REF | 0x10,
                            4,
                            &mut out,
                        );
                    } else if *index < base {
                        encode_int_vec(
                            base - index - 1,
                            LITERAL_WITH_NAME_REF,
                            4,
                            &mut out,
                        );
                    } else {
                        encode_int_vec(index - base, 0x00, 3, &mut out);
                    }
                    encode_string_vec(value, 0x00, 7, false, strict, &mut out);
                },

                Representation::Literal { name, value } => {
                    encode_string_vec(name, LITERAL, 3, true, strict, &mut out);
                    encode_string_vec(value, 0x00, 7, false, strict, &mut out);
                },
            }
        }

        out
    }
}

/// The oldest quarter of the table isn't referred to, so its entries can
/// drain and be evicted (qpack_encoder.cc, kDrainingFraction).
const DRAINING_FRACTION: f64 = 0.25;

/// RFC 9204, Section 3.2.1.
fn entry_size(name: &[u8], value: &[u8]) -> u64 {
    (name.len() + value.len() + 32) as u64
}

/// The fields of `headers` in order, a `cookie` split into crumbs at each
/// `;` and the space after it, and any value split at NUL bytes
/// (value_splitting_header_list.cc, with cookie crumbling on as Chromium
/// has it).
fn split_values<T: NameValue>(headers: &[T]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::with_capacity(headers.len());

    for h in headers {
        let name = h.name().to_ascii_lowercase();

        if name == b"cookie" {
            for crumb in h.value().split(|&b| b == b';') {
                let crumb = crumb.strip_prefix(b" ").unwrap_or(crumb);
                out.push((name.clone(), crumb.to_vec()));
            }
            continue;
        }

        for part in h.value().split(|&b| b == 0) {
            out.push((name.clone(), part.to_vec()));
        }
    }

    out
}

/// One field line before its dynamic indices are made relative.
#[derive(Debug, PartialEq, Eq)]
enum Representation {
    Indexed {
        is_static: bool,
        index: u64,
    },
    NameReference {
        is_static: bool,
        index: u64,
        value: Vec<u8>,
    },
    Literal {
        name: Vec<u8>,
        value: Vec<u8>,
    },
}

impl Representation {
    fn dynamic_index(&self) -> Option<u64> {
        match self {
            Representation::Indexed {
                is_static: false,
                index,
            } |
            Representation::NameReference {
                is_static: false,
                index,
                ..
            } => Some(*index),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Match {
    NameAndValue { is_static: bool, index: u64 },
    Name { is_static: bool, index: u64 },
    None,
}

/// The encoder's copy of the peer's dynamic table
/// (qpack_header_table.cc, QpackEncoderHeaderTable).
#[derive(Default)]
struct Table {
    /// The peer's SETTINGS_QPACK_MAX_TABLE_CAPACITY, which Required
    /// Insert Count is encoded against.
    max_capacity: u64,
    capacity: u64,
    size: u64,
    /// The newest last.
    entries: VecDeque<(Vec<u8>, Vec<u8>)>,
    dropped: u64,
}

impl Table {
    fn inserted(&self) -> u64 {
        self.dropped + self.entries.len() as u64
    }

    fn max_entries(&self) -> u64 {
        (self.max_capacity / 32).max(1)
    }

    fn set_capacity(&mut self, capacity: u64) {
        self.capacity = capacity;
        self.evict_to(capacity);
    }

    fn evict_to(&mut self, size: u64) {
        while self.size > size {
            let Some((n, v)) = self.entries.pop_front() else {
                break;
            };
            self.size -= entry_size(&n, &v);
            self.dropped += 1;
        }
    }

    /// Inserts an entry, evicting the oldest ones to make room, and
    /// returns its absolute index.
    fn insert(&mut self, name: &[u8], value: &[u8]) -> u64 {
        let size = entry_size(name, value);
        self.evict_to(self.capacity.saturating_sub(size));
        self.size += size;
        self.entries.push_back((name.to_vec(), value.to_vec()));
        self.inserted() - 1
    }

    /// QUICHE's `FindHeaderField`: an exact match in the static table,
    /// then the newest exact one in the dynamic table, then the name.
    fn find(&self, name: &[u8], value: &[u8]) -> Match {
        if let Some((index, true)) = lookup_static(&(name, value)) {
            return Match::NameAndValue {
                is_static: true,
                index,
            };
        }

        if let Some(at) = self
            .entries
            .iter()
            .rposition(|(n, v)| n == name && v == value)
        {
            return Match::NameAndValue {
                is_static: false,
                index: self.dropped + at as u64,
            };
        }

        self.find_name(name)
    }

    /// QUICHE's `FindHeaderName`: the static table first, then the newest
    /// entry with that name.
    fn find_name(&self, name: &[u8]) -> Match {
        if let Some((index, _)) = lookup_static(&(name, b"")) {
            return Match::Name {
                is_static: true,
                index,
            };
        }

        if let Some(at) = self.entries.iter().rposition(|(n, _)| n == name) {
            return Match::Name {
                is_static: false,
                index: self.dropped + at as u64,
            };
        }

        Match::None
    }

    /// QUICHE's `MaxInsertSizeWithoutEvictingGivenEntry`: how large an
    /// entry can be inserted without evicting the one at `index`.
    fn max_insert_size_without_evicting(&self, index: u64) -> u64 {
        if index > self.inserted() {
            return self.capacity;
        }

        let free = self.capacity.saturating_sub(self.size);

        // The entries older than `index` can be evicted to make room.
        (self.dropped..)
            .zip(&self.entries)
            .take_while(|(at, _)| *at < index)
            .fold(free, |max, (_, (n, v))| max + entry_size(n, v))
    }

    /// QUICHE's `draining_index`: the oldest entries, as many as leave
    /// `fraction` of the capacity free above them, aren't referred to.
    fn draining_index(&self, fraction: f64) -> u64 {
        let required = (fraction * self.capacity as f64) as u64;
        let mut space = self.capacity.saturating_sub(self.size);

        if self.entries.is_empty() || space >= required {
            return self.dropped;
        }

        let mut index = self.dropped;

        for (i, (n, v)) in self.entries.iter().enumerate() {
            if space >= required {
                break;
            }
            space += entry_size(n, v);
            index += 1;
            if i + 1 == self.entries.len() {
                return self.inserted();
            }
        }

        index
    }
}

/// Which entries the peer's decoder has, and which field sections it
/// hasn't acknowledged yet (new_qpack_blocking_manager.cc).
#[derive(Default)]
struct Blocking {
    known_received_count: u64,

    /// Each stream's unacknowledged field sections, oldest first: their
    /// Required Insert Count and the entries they refer to.
    streams: HashMap<u64, VecDeque<(u64, Vec<u64>)>>,

    /// How many unacknowledged sections refer to each entry.
    references: BTreeMap<u64, u64>,
}

impl Blocking {
    fn smallest_blocking_index(&self) -> u64 {
        self.references.keys().next().copied().unwrap_or(u64::MAX)
    }

    fn stream_is_blocked(&self, stream_id: u64) -> bool {
        self.streams.get(&stream_id).is_some_and(|sections| {
            sections
                .iter()
                .any(|(ric, _)| *ric > self.known_received_count)
        })
    }

    fn blocking_allowed_on_stream(&self, stream_id: u64, max: u64) -> bool {
        let blocked = self
            .streams
            .keys()
            .filter(|&&id| self.stream_is_blocked(id))
            .count() as u64;

        blocked < max || self.stream_is_blocked(stream_id)
    }

    fn on_header_block_sent(
        &mut self, stream_id: u64, indices: Vec<u64>, required_insert_count: u64,
    ) {
        for &i in &indices {
            *self.references.entry(i).or_default() += 1;
        }

        self.streams
            .entry(stream_id)
            .or_default()
            .push_back((required_insert_count, indices));
    }

    fn release(&mut self, indices: &[u64]) {
        for i in indices {
            if let Some(n) = self.references.get_mut(i) {
                *n -= 1;
                if *n == 0 {
                    self.references.remove(i);
                }
            }
        }
    }

    fn on_header_acknowledgement(&mut self, stream_id: u64) -> bool {
        let Some(sections) = self.streams.get_mut(&stream_id) else {
            return false;
        };

        let Some((ric, indices)) = sections.pop_front() else {
            return false;
        };

        if sections.is_empty() {
            self.streams.remove(&stream_id);
        }

        self.known_received_count = self.known_received_count.max(ric);
        self.release(&indices);

        true
    }

    fn on_stream_cancellation(&mut self, stream_id: u64) {
        if let Some(sections) = self.streams.remove(&stream_id) {
            for (_, indices) in sections {
                self.release(&indices);
            }
        }
    }
}

/// `encode_int`, onto a growing buffer.
fn encode_int_vec(v: u64, first: u8, prefix: usize, out: &mut Vec<u8>) {
    let mut buf = [0; 11];
    let mut b = octets::OctetsMut::with_slice(&mut buf);
    // Eleven bytes hold any u64 with any prefix.
    encode_int(v, first, prefix, &mut b).expect("an integer fits");
    let len = b.off();
    out.extend_from_slice(&buf[..len]);
}

/// A string with its length's `prefix` bits and the Huffman flag just
/// above them, Huffman-coded when that's shorter, or with `strict` off
/// when it's no longer.
fn encode_string_vec(
    v: &[u8], first: u8, prefix: usize, lower_case: bool, strict: bool,
    out: &mut Vec<u8>,
) {
    let huffman_len = if lower_case {
        octets::huffman_encoding_len::<true>(v)
    } else {
        octets::huffman_encoding_len::<false>(v)
    };

    let mut buf = vec![0; v.len() + 11];
    let mut b = octets::OctetsMut::with_slice(&mut buf);

    match huffman_len {
        Ok(len) if !strict || len < v.len() => {
            encode_int(len as u64, first | (1 << prefix), prefix, &mut b)
                .expect("an integer fits");
            if lower_case {
                b.put_huffman_encoded::<true>(v)
            } else {
                b.put_huffman_encoded::<false>(v)
            }
            .expect("the Huffman code fits");
        },

        _ => {
            encode_int(v.len() as u64, first, prefix, &mut b)
                .expect("an integer fits");
            if lower_case {
                b.put_bytes(&v.to_ascii_lowercase())
            } else {
                b.put_bytes(v)
            }
            .expect("the string fits");
        },
    }

    let len = b.off();
    out.extend_from_slice(&buf[..len]);
}

fn lookup_static<T: NameValue>(h: &T) -> Option<(u64, bool)> {
    // Fetch the right encoding table for this header length.
    let table_for_len =
        super::static_table::STATIC_ENCODE_TABLE.get(h.name().len())?;

    // Similar to [`eq_ignore_ascii_case`], but only lowercases the second
    // operand, as the entries in the table are already lower cased.
    let cmp_lowercase = |a: &[u8], b: &[u8]| {
        std::iter::zip(a, b).all(|(a, b)| a.eq(&b.to_ascii_lowercase()))
    };

    for (name, values) in table_for_len.iter() {
        // Match header name first.
        if cmp_lowercase(name, h.name()) {
            // Second iterate over possible values for the header.
            for (value, enc) in values.iter() {
                // Match header value.
                if value.is_empty() {
                    return Some((*enc, false));
                }

                if h.value() == *value {
                    return Some((*enc, true));
                }
            }
            // Only matched the header, not the value.
            return Some((values.first()?.1, false));
        }
    }

    None
}

pub fn encode_int(
    mut v: u64, first: u8, prefix: usize, b: &mut octets::OctetsMut,
) -> Result<()> {
    let mask = 2u64.pow(prefix as u32) - 1;

    // Encode I on N bits.
    if v < mask {
        b.put_u8(first | v as u8)?;
        return Ok(());
    }

    // Encode (2^N - 1) on N bits.
    b.put_u8(first | mask as u8)?;

    v -= mask;

    while v >= 128 {
        // Encode (I % 128 + 128) on 8 bits.
        b.put_u8((v % 128 + 128) as u8)?;

        v >>= 7;
    }

    // Encode I on 8 bits.
    b.put_u8(v as u8)?;

    Ok(())
}

#[inline]
pub fn encode_str<const LOWER_CASE: bool>(
    v: &[u8], first: u8, prefix: usize, b: &mut octets::OctetsMut,
) -> Result<()> {
    // Huffman-encoding generally saves space but in some cases it doesn't, for
    // those just encode the literal string.
    match octets::huffman_encoding_len::<LOWER_CASE>(v) {
        Ok(len) => {
            encode_int(len as u64, first | (1 << prefix), prefix, b)?;
            b.put_huffman_encoded::<LOWER_CASE>(v)?;
        },

        Err(_) => {
            encode_int(v.len() as u64, first, prefix, b)?;
            if LOWER_CASE {
                b.put_bytes(&v.to_ascii_lowercase())?;
            } else {
                b.put_bytes(v)?;
            }
        },
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_int1() {
        let expected = [0b01010];
        let mut encoded = [0; 1];
        let mut b = octets::OctetsMut::with_slice(&mut encoded);

        assert!(encode_int(10, 0, 5, &mut b).is_ok());

        assert_eq!(expected, encoded);
    }

    #[test]
    fn encode_int2() {
        let expected = [0b11111, 0b10011010, 0b00001010];
        let mut encoded = [0; 3];
        let mut b = octets::OctetsMut::with_slice(&mut encoded);

        assert!(encode_int(1337, 0, 5, &mut b).is_ok());

        assert_eq!(expected, encoded);
    }

    #[test]
    fn encode_int3() {
        let expected = [0b101010];
        let mut encoded = [0; 1];
        let mut b = octets::OctetsMut::with_slice(&mut encoded);

        assert!(encode_int(42, 0, 8, &mut b).is_ok());

        assert_eq!(expected, encoded);
    }

    #[test]
    fn encode_static_header() {
        let mut encoded = [0; 3];
        Encoder::default()
            .encode(&[(b":method", b"GET")], &mut encoded)
            .unwrap();
        assert_eq!(encoded, [0, 0, INDEXED | 0x40 | 17]);
    }

    #[test]
    fn encode_static_header_name_only() {
        let mut encoded = [0; 11];
        let mut expected = [0; 11];
        let mut buf = octets::OctetsMut::with_slice(&mut expected[..]);
        buf.put_u16(0).unwrap();
        buf.put_u8(LITERAL_WITH_NAME_REF | 0x10 | 15).unwrap();
        buf.put_u8(0).unwrap();
        encode_str::<false>(b"FORGET", 0, 7, &mut buf).unwrap();

        Encoder::default()
            .encode(&[(b":method", b"FORGET")], &mut encoded)
            .unwrap();
        assert_eq!(encoded, expected);
    }

    // netweir: Chromium's encoder.

    fn chromium() -> Encoder {
        Encoder::with_mode(Mode::Chromium, 65536)
    }

    fn encode_on(
        enc: &mut Encoder, stream_id: u64, headers: &[(&[u8], &[u8])],
    ) -> Vec<u8> {
        let mut out = vec![0; 1024];
        let len = enc.encode_for_stream(stream_id, headers, &mut out).unwrap();
        out.truncate(len);
        out
    }

    #[test]
    fn chromium_before_settings_uses_no_table_and_huffman_only_if_shorter() {
        // Chrome 157's first request, encoded before the server's SETTINGS:
        // "?0" Huffman-codes to 15 bits, no shorter than its 2 bytes, so
        // it goes as it is (profiles/chrome-157-macos.h3-qpack).
        let mut enc = chromium();
        let block = encode_on(&mut enc, 0, &[(b"sec-ch-ua-mobile", b"?0")]);
        assert!(enc.take_instructions().is_empty());
        let mut expected = vec![0, 0];
        encode_string_vec(
            b"sec-ch-ua-mobile",
            LITERAL,
            3,
            true,
            true,
            &mut expected,
        );
        expected.extend_from_slice(&[0x02, b'?', b'0']);
        assert_eq!(block, expected);

        // Upstream quiche Huffman-codes it.
        let mut out = [0; 64];
        let len = Encoder::new()
            .encode(&[(b"sec-ch-ua-mobile", b"?0")], &mut out)
            .unwrap();
        assert_ne!(&out[..len], &expected[..]);
    }

    #[test]
    fn chromium_inserts_and_refers_from_the_required_insert_count() {
        let mut enc = chromium();
        enc.on_peer_settings(Some(65536), Some(100));
        let block = encode_on(&mut enc, 4, &[
            (b":method", b"GET"),
            (b":authority", b"localhost"),
            (b"sec-fetch-mode", b"cors"),
        ]);

        // Set Dynamic Table Capacity 65536; Insert With Name Reference,
        // static 0; Insert With Literal Name.
        let mut instructions = Vec::new();
        encode_int_vec(65536, 0x20, 5, &mut instructions);
        encode_int_vec(0, 0xc0, 6, &mut instructions);
        encode_string_vec(b"localhost", 0, 7, false, true, &mut instructions);
        encode_string_vec(
            b"sec-fetch-mode",
            0x40,
            5,
            true,
            true,
            &mut instructions,
        );
        encode_string_vec(b"cors", 0, 7, false, true, &mut instructions);
        assert_eq!(enc.take_instructions(), instructions);

        // Required Insert Count 2, encoded 3; Base 2 (delta 0); static 17,
        // then dynamic entries 0 and 1 as relative 1 and 0.
        assert_eq!(block, [0x03, 0x00, 0xd1, 0x81, 0x80]);

        // The same fields again: references only, nothing inserted.
        let block = encode_on(&mut enc, 8, &[
            (b":authority", b"localhost"),
            (b"sec-fetch-mode", b"cors"),
        ]);
        assert!(enc.take_instructions().is_empty());
        assert_eq!(block, [0x03, 0x00, 0x81, 0x80]);
    }

    #[test]
    fn chromium_inserts_a_new_value_under_a_dynamic_name() {
        let mut enc = chromium();
        enc.on_peer_settings(Some(65536), Some(100));
        encode_on(&mut enc, 0, &[(b"sec-fetch-mode", b"cors")]);
        enc.take_instructions();
        let block = encode_on(&mut enc, 4, &[(b"sec-fetch-mode", b"no-cors")]);
        // Insert With Name Reference to dynamic entry 0, relative 0.
        let mut instructions = vec![0x80];
        encode_string_vec(b"no-cors", 0, 7, false, true, &mut instructions);
        assert_eq!(enc.take_instructions(), instructions);
        assert_eq!(block, [0x03, 0x00, 0x80]);
    }

    #[test]
    fn chromium_inserts_nothing_when_no_stream_may_block() {
        // QUICHE inserts only where it may refer to the entry at once.
        let mut enc = chromium();
        enc.on_peer_settings(Some(65536), Some(0));
        let block = encode_on(&mut enc, 0, &[(b"sec-fetch-mode", b"cors")]);
        let mut capacity = Vec::new();
        encode_int_vec(65536, 0x20, 5, &mut capacity);
        assert_eq!(enc.take_instructions(), capacity);
        assert_eq!(&block[..2], [0, 0]);
    }

    #[test]
    fn chromium_caps_the_table_at_its_own_capacity() {
        let mut enc = chromium();
        enc.on_peer_settings(Some(1 << 20), Some(100));
        let mut capacity = Vec::new();
        encode_int_vec(65536, 0x20, 5, &mut capacity);
        assert_eq!(enc.take_instructions(), capacity);
    }

    #[test]
    fn chromium_refers_to_acknowledged_entries_once_streams_cant_block() {
        let mut enc = chromium();
        enc.on_peer_settings(Some(65536), Some(1));
        encode_on(&mut enc, 0, &[(b"x-a", b"1")]);
        // Stream 0 is blocked, the one stream allowed: stream 4 can't refer
        // to the entry, nor insert.
        let block = encode_on(&mut enc, 4, &[(b"x-a", b"1")]);
        assert_eq!(&block[..2], [0, 0], "a literal");
        // Section Acknowledgment for stream 0: the entry is known now.
        enc.on_decoder_stream(&[0x80]).unwrap();
        let block = encode_on(&mut enc, 8, &[(b"x-a", b"1")]);
        assert_eq!(block, [0x02, 0x00, 0x80]);
    }

    #[test]
    fn chromium_duplicates_a_draining_entry() {
        // A 188-byte table: "x-a: N" is 36 bytes, so after four entries 44
        // bytes are free, under a quarter (47), and the oldest drains; a
        // copy of it still fits without evicting it.
        let mut enc = Encoder::with_mode(Mode::Chromium, 188);
        enc.on_peer_settings(Some(188), Some(100));
        for (i, v) in [b"1", b"2", b"3", b"4"].iter().enumerate() {
            encode_on(&mut enc, i as u64 * 4, &[(b"x-a", &v[..])]);
            enc.on_decoder_stream(&[0x80 | (i as u8 * 4)]).unwrap();
        }
        enc.take_instructions();
        let block = encode_on(&mut enc, 16, &[(b"x-a", b"1")]);
        // Duplicate relative 3 (entry 0 of 4); then Required Insert Count
        // 5, encoded 5 % 10 + 1, and the copy as relative 0.
        assert_eq!(enc.take_instructions(), [0x03]);
        assert_eq!(block, [0x06, 0x00, 0x80]);
    }

    #[test]
    fn chromium_wont_evict_the_entry_it_would_duplicate() {
        // A 128-byte table, three entries in it, 20 bytes free: copying the
        // draining entry 0 would evict it, so the value goes in under the
        // newest entry's name (qpack_encoder.cc, the fallthrough to kName).
        let mut enc = Encoder::with_mode(Mode::Chromium, 128);
        enc.on_peer_settings(Some(128), Some(100));
        for (i, v) in [b"1", b"2", b"3"].iter().enumerate() {
            encode_on(&mut enc, i as u64 * 4, &[(b"x-a", &v[..])]);
            enc.on_decoder_stream(&[0x80 | (i as u8 * 4)]).unwrap();
        }
        enc.take_instructions();
        encode_on(&mut enc, 12, &[(b"x-a", b"1")]);
        assert_eq!(enc.take_instructions(), [0x80, 0x01, b'1']);
    }

    #[test]
    fn decoder_stream_instructions_in_pieces() {
        let mut enc = chromium();
        enc.on_peer_settings(Some(65536), Some(100));
        encode_on(&mut enc, 200, &[(b"x-a", b"1")]);
        // Section Acknowledgment for stream 200: 0xff, then 200 - 127 = 73.
        enc.on_decoder_stream(&[0xff]).unwrap();
        enc.on_decoder_stream(&[73]).unwrap();
        assert_eq!(enc.blocking.known_received_count, 1);
        assert_eq!(enc.on_decoder_stream(&[0x80]), Err(Error::DecoderStream));
        let mut enc = chromium();
        assert_eq!(enc.on_decoder_stream(&[0x00]), Err(Error::DecoderStream));
        assert_eq!(enc.on_decoder_stream(&[0x01]), Err(Error::DecoderStream));
    }

    // netweir: Safari's encoder, as profiles/safari-27-macos.h3-qpack
    // recorded it.

    fn safari(blocked_streams: u64) -> Encoder {
        let mut enc = Encoder::with_mode(Mode::Safari, SAFARI_MAX_TABLE_CAPACITY);
        enc.on_peer_settings(Some(1 << 20), Some(blocked_streams));
        enc
    }

    const FETCH: &[(&[u8], &[u8])] = &[
        (b":method", b"GET"),
        (b":authority", b"localhost"),
        (b"sec-fetch-mode", b"cors"),
        (b"accept", b"*/*"),
    ];

    #[test]
    fn safari_inserts_a_field_the_second_time_it_is_sent() {
        let mut enc = safari(100);

        // The first time: names from the static table, else literals.
        let first = encode_on(&mut enc, 0, FETCH);
        let mut capacity = Vec::new();
        encode_int_vec(SAFARI_MAX_TABLE_CAPACITY, 0x20, 5, &mut capacity);
        assert_eq!(enc.take_instructions(), capacity, "65536, not 1 MiB");
        let mut expected = vec![0, 0, 0xd1];
        encode_int_vec(0, LITERAL_WITH_NAME_REF | 0x10, 4, &mut expected);
        encode_string_vec(b"localhost", 0, 7, false, false, &mut expected);
        encode_string_vec(
            b"sec-fetch-mode",
            LITERAL,
            3,
            true,
            false,
            &mut expected,
        );
        encode_string_vec(b"cors", 0, 7, false, false, &mut expected);
        expected.push(0xc0 | 29);
        assert_eq!(first, expected);

        // The second time: inserted, under the static name and a literal
        // one, and referred to past Base 0 (Required Insert Count 2,
        // encoded 3; sign 1, delta 1).
        let second = encode_on(&mut enc, 4, FETCH);
        let mut inserts = vec![0xc0];
        encode_string_vec(b"localhost", 0, 7, false, false, &mut inserts);
        encode_string_vec(b"sec-fetch-mode", 0x40, 5, true, false, &mut inserts);
        encode_string_vec(b"cors", 0, 7, false, false, &mut inserts);
        assert_eq!(enc.take_instructions(), inserts);
        assert_eq!(second, [0x03, 0x81, 0xd1, 0x10, 0x11, 0xc0 | 29]);

        // Then from below Base 2.
        let third = encode_on(&mut enc, 8, FETCH);
        assert!(enc.take_instructions().is_empty());
        assert_eq!(third, [0x03, 0x00, 0xd1, 0x81, 0x80, 0xc0 | 29]);
    }

    #[test]
    fn safari_puts_a_new_value_under_a_dynamic_name() {
        let mut enc = safari(100);
        for stream in [0, 4] {
            encode_on(&mut enc, stream, &[(b"sec-fetch-mode", b"cors")]);
        }
        enc.take_instructions();
        // First time for "no-cors": the dynamic entry's name.
        let first = encode_on(&mut enc, 8, &[(b"sec-fetch-mode", b"no-cors")]);
        let mut expected = vec![0x02, 0x00, LITERAL_WITH_NAME_REF];
        encode_string_vec(b"no-cors", 0, 7, false, false, &mut expected);
        assert_eq!(first, expected);
        // Second: inserted with that name, relative 0.
        encode_on(&mut enc, 12, &[(b"sec-fetch-mode", b"no-cors")]);
        let mut inserts = vec![0x80];
        encode_string_vec(b"no-cors", 0, 7, false, false, &mut inserts);
        assert_eq!(enc.take_instructions(), inserts);
    }

    #[test]
    fn safari_without_blocked_streams_inserts_but_waits_to_refer() {
        let mut enc = safari(0);
        encode_on(&mut enc, 0, FETCH);
        enc.take_instructions();
        let second = encode_on(&mut enc, 4, FETCH);
        assert_eq!(&second[..2], [0, 0], "nothing referred to yet");
        assert!(!enc.take_instructions().is_empty(), "but inserted");
        // Acknowledged by an Insert Count Increment of 2.
        enc.on_decoder_stream(&[0x02]).unwrap();
        let third = encode_on(&mut enc, 8, FETCH);
        assert_eq!(third, [0x03, 0x00, 0xd1, 0x81, 0x80, 0xc0 | 29]);

        // An insert that would name a dynamic entry is left out.
        encode_on(&mut enc, 12, &[(b"sec-fetch-mode", b"no-cors")]);
        encode_on(&mut enc, 16, &[(b"sec-fetch-mode", b"no-cors")]);
        assert!(enc.take_instructions().is_empty());
    }

    #[test]
    fn safari_uses_no_table_before_the_servers_settings() {
        let mut enc = Encoder::with_mode(Mode::Safari, SAFARI_MAX_TABLE_CAPACITY);
        encode_on(&mut enc, 0, FETCH);
        enc.on_peer_settings(Some(65536), Some(100));
        enc.take_instructions();
        // What was sent before doesn't count: this is the first time.
        let block = encode_on(&mut enc, 4, FETCH);
        assert!(enc.take_instructions().is_empty());
        assert_eq!(&block[..2], [0, 0]);
    }

    #[test]
    fn cookies_are_crumbled() {
        let mut enc = chromium();
        let block = encode_on(&mut enc, 0, &[(b"cookie", b"a=1; b=2")]);
        let mut expected = vec![0, 0];
        for crumb in [&b"a=1"[..], b"b=2"] {
            encode_int_vec(5, LITERAL_WITH_NAME_REF | 0x10, 4, &mut expected);
            encode_string_vec(crumb, 0, 7, false, true, &mut expected);
        }
        assert_eq!(block, expected);
    }
}
