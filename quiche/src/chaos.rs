// This file ports code from Google QUICHE, which carries this notice:
//
// Copyright 2021 The Chromium Authors. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! netweir: the layout of a client's Initial packets as Chromium's QUIC
//! makes it, so that the ClientHello can't be read from one packet in one
//! piece.
//!
//! A port of Google QUICHE's `QuicChaosProtector`
//! (quiche/quic/core/quic_chaos_protector.cc) and of the first-flight split
//! in `QuicPacketCreator::MultiPacketChaosProtect`
//! (quiche/quic/core/quic_packet_creator.cc). The steps, their order,
//! the constants and the way each random number is drawn follow that
//! code; QUICHE's frames are reduced to the three kinds a client's
//! Initial carries here.

use crate::rand::rand_u64;

/// A frame of a chaos-protected Initial packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Frame {
    Crypto { offset: u64, len: usize },

    Ping,

    Padding(usize),
}

/// The bytes a CRYPTO frame takes besides its data, its length written
/// in as few bytes as it takes (`QuicFramer::GetMinCryptoFrameSize`).
pub(crate) fn crypto_overhead(offset: u64, len: usize) -> usize {
    1 + octets::varint_len(offset) + octets::varint_len(len as u64)
}

/// How the first `write_len` bytes of CRYPTO data are split when they don't
/// fit in one packet of `capacity` bytes of frames: the first packet takes
/// a first frame of 55 to 86 bytes, the ClientHello's mostly fixed start
/// and its first extension's header, and a last frame with the end of the
/// data; the middle goes to the next packets, the data spread evenly
/// across all of them. Returns the first and last frames' lengths, or
/// `None` when the data fits in one packet or the split can't be made.
///
/// `MultiPacketChaosProtect`, with `capacity` standing for both
/// `BytesFree()` of the first packet and `max_plaintext_size_ -
/// PacketHeaderSize()` of the others.
pub(crate) fn split_first_flight(
    capacity: usize, write_len: usize,
) -> Option<(usize, usize)> {
    if write_len == 0 {
        return None;
    }

    let min_crypto_frame_size =
        crypto_overhead(write_len as u64 - 1, write_len);

    if capacity < 2 * min_crypto_frame_size {
        return None;
    }

    let max_first = capacity - 2 * min_crypto_frame_size;
    let max_other = capacity.checked_sub(min_crypto_frame_size)?;

    if write_len <= max_first {
        return None;
    }

    let first_occupied = max_other - max_first;
    let num_packets = (write_len + first_occupied + max_other - 1) / max_other;
    let in_other = (write_len + first_occupied + num_packets - 1) / num_packets;

    if in_other < first_occupied {
        return None;
    }

    let in_first = in_other - first_occupied;

    const MIN_FIRST_FRAME_LENGTH: usize = 55;
    const FIRST_FRAME_LENGTH_RANDOM: u64 = 32;

    let first_len = MIN_FIRST_FRAME_LENGTH +
        (rand_u64() % FIRST_FRAME_LENGTH_RANDOM) as usize;

    if write_len <= first_len || in_first <= first_len {
        return None;
    }

    Some((first_len, in_first - first_len))
}

/// The frames of one packet carrying `crypto` (offset and length of each
/// CRYPTO frame, in the order they were queued) and `padding` bytes of
/// room left, laid out as `QuicChaosProtector::BuildDataPacket` lays them
/// out: CRYPTO frames split at random, PING frames added, the padding
/// spread between frames, then everything shuffled. With no room left
/// it's the CRYPTO frames as they came, as QUICHE then builds the packet
/// without chaos protection.
pub(crate) fn protect(crypto: &[(u64, usize)], padding: usize) -> Vec<Frame> {
    let mut frames: Vec<Frame> = crypto
        .iter()
        .map(|&(offset, len)| Frame::Crypto { offset, len })
        .collect();

    if frames.is_empty() || padding == 0 {
        return frames;
    }

    let start = crypto.iter().map(|c| c.0).min().unwrap_or(0);
    let end = crypto
        .iter()
        .map(|c| c.0 + c.1 as u64)
        .max()
        .unwrap_or(0);

    let mut remaining = padding as i64;

    split_crypto_frames(&mut frames, start, (end - start) as usize, &mut remaining);
    add_ping_frames(&mut frames, &mut remaining);
    spread_padding(&mut frames, &mut remaining);
    reorder_frames(&mut frames);

    frames
}

/// `QuicChaosProtector::SplitCryptoFrame`.
fn split_crypto_frames(
    frames: &mut Vec<Frame>, start: u64, len: usize, remaining: &mut i64,
) {
    let max_overhead = crypto_overhead(start + len as u64, len) as i64;

    const MIN_ADDED_CRYPTO_FRAMES: u64 = 2;
    const MAX_ADDED_CRYPTO_FRAMES: u64 = 10;

    let added = MIN_ADDED_CRYPTO_FRAMES +
        rand_u64() % (MAX_ADDED_CRYPTO_FRAMES + 1 - MIN_ADDED_CRYPTO_FRAMES);

    for _ in 0..added {
        if *remaining < max_overhead {
            break;
        }

        let index = (rand_u64() % frames.len() as u64) as usize;

        let Frame::Crypto { offset, len } = frames[index] else {
            continue;
        };

        if len <= 1 {
            continue;
        }

        let old_overhead = crypto_overhead(offset, len) as i64;

        let first_len = 1 + (rand_u64() % (len as u64 - 1)) as usize;
        let new_len = len - first_len;
        let new_offset = offset + first_len as u64;

        frames[index] = Frame::Crypto {
            offset,
            len: first_len,
        };
        frames.push(Frame::Crypto {
            offset: new_offset,
            len: new_len,
        });

        *remaining -= crypto_overhead(new_offset, new_len) as i64;
        *remaining -= crypto_overhead(offset, first_len) as i64;
        *remaining += old_overhead;
    }
}

/// `QuicChaosProtector::AddPingFrames`.
fn add_ping_frames(frames: &mut Vec<Frame>, remaining: &mut i64) {
    if *remaining == 0 {
        return;
    }

    const MIN_ADDED_PING_FRAMES: u64 = 2;
    const MAX_ADDED_PING_FRAMES: u64 = 10;

    let pings = (MIN_ADDED_PING_FRAMES +
        rand_u64() % (MAX_ADDED_PING_FRAMES + 1 - MIN_ADDED_PING_FRAMES))
        .min(*remaining as u64);

    for _ in 0..pings {
        frames.push(Frame::Ping);
    }

    *remaining -= pings as i64;
}

/// `QuicChaosProtector::SpreadPadding`.
fn spread_padding(frames: &mut Vec<Frame>, remaining: &mut i64) {
    let mut i = 0;

    while i < frames.len() {
        let here = (rand_u64() % (*remaining as u64 + 1)) as i64;

        if here > 0 {
            frames.insert(i, Frame::Padding(here as usize));
            // Skip over the padding just added.
            i += 1;
            *remaining -= here;
        }

        i += 1;
    }

    if *remaining > 0 {
        frames.push(Frame::Padding(*remaining as usize));
    }
}

/// `QuicChaosProtector::ReorderFrames`: walks the frames backwards,
/// swapping each with a random earlier one.
fn reorder_frames(frames: &mut [Frame]) {
    for i in (1..frames.len()).rev() {
        let j = (rand_u64() % (i as u64 + 1)) as usize;
        frames.swap(i, j);
    }
}

/// The bytes `frames` take on the wire.
pub(crate) fn wire_len(frames: &[Frame]) -> usize {
    frames
        .iter()
        .map(|f| match *f {
            Frame::Crypto { offset, len } => crypto_overhead(offset, len) + len,
            Frame::Ping => 1,
            Frame::Padding(n) => n,
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_flight_split_like_chromium() {
        // The payload room of a 1250-byte Initial with an 8-byte DCID and
        // no SCID, and the 1974 bytes of one of Chrome 157's ClientHellos.
        let capacity = 1250 - (1 + 4 + 1 + 8 + 1 + 1 + 2 + 1) - 16;
        for _ in 0..1000 {
            let (first, last) = split_first_flight(capacity, 1974).unwrap();
            assert!((55..87).contains(&first));
            // Data spread evenly over two packets, the first holding one
            // frame more.
            assert_eq!(first + last, 985);
        }
        assert_eq!(split_first_flight(capacity, 600), None);
    }

    #[test]
    fn frames_fill_the_packet_and_cover_the_data() {
        let crypto = [(0u64, 70usize), (1060, 914)];
        let room = 1215 - wire_len(&protect(&crypto, 0));
        let (mut cryptos, mut pings, mut layouts) =
            (Vec::new(), Vec::new(), std::collections::HashSet::new());
        for _ in 0..2000 {
            let frames = protect(&crypto, room);
            assert_eq!(wire_len(&frames), 1215);
            let mut covered: Vec<(u64, usize)> = frames
                .iter()
                .filter_map(|f| match *f {
                    Frame::Crypto { offset, len } => Some((offset, len)),
                    _ => None,
                })
                .collect();
            cryptos.push(covered.len());
            pings.push(frames.iter().filter(|f| **f == Frame::Ping).count());
            covered.sort();
            let mut at = 0;
            let mut ranges = Vec::new();
            for (offset, len) in covered {
                if offset != at {
                    ranges.push((at, offset));
                }
                at = offset + len as u64;
            }
            assert_eq!(ranges, vec![(70, 1060)]);
            assert_eq!(at, 1974);
            layouts.insert(format!("{frames:?}"));
        }
        // 2 frames plus 2 to 10 splits, some of which may miss.
        assert!(cryptos.iter().all(|&n| (2..=12).contains(&n)));
        assert_eq!(*pings.iter().min().unwrap(), 2);
        assert_eq!(*pings.iter().max().unwrap(), 10);
        assert!(layouts.len() > 1990);
    }
}
