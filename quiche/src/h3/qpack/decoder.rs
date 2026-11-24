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

use super::dynamic_table::DynamicTable;
use super::dynamic_table::TableError;
use super::Error;
use super::Result;

use crate::h3::Header;

use super::INDEXED;
use super::INDEXED_WITH_POST_BASE;
use super::LITERAL;
use super::LITERAL_WITH_NAME_REF;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Representation {
    Indexed,
    IndexedWithPostBase,
    Literal,
    LiteralWithNameRef,
    LiteralWithPostBase,
}

impl Representation {
    pub fn from_byte(b: u8) -> Representation {
        if b & INDEXED == INDEXED {
            return Representation::Indexed;
        }

        if b & LITERAL_WITH_NAME_REF == LITERAL_WITH_NAME_REF {
            return Representation::LiteralWithNameRef;
        }

        if b & LITERAL == LITERAL {
            return Representation::Literal;
        }

        if b & INDEXED_WITH_POST_BASE == INDEXED_WITH_POST_BASE {
            return Representation::IndexedWithPostBase;
        }

        Representation::LiteralWithPostBase
    }
}

/// Helper for tracking decoded field list sizes.
///
/// The size of a field list is calculated based on the uncompressed size of
/// fields, including the length of the name and value in bytes plus an overhead
/// of 32 bytes for each field. See
/// <https://datatracker.ietf.org/doc/html/rfc9114#section-4.2.2>
struct FieldListSizeTracker {
    remaining: u64,
}

impl FieldListSizeTracker {
    /// Initialize tracker with the maximum field list size.
    ///
    /// The `max_size` parameter is the maximum size in bytes of the full
    /// decoded field list. See
    /// <https://datatracker.ietf.org/doc/html/rfc9114#section-4.2.2>
    fn new(max_size: u64) -> Self {
        Self {
            remaining: max_size,
        }
    }

    /// Mark the start of parsing a new field.
    ///
    /// Must be called when a new field is ready to be parsed.
    fn on_field_start(&mut self) -> Result<()> {
        // Each complete field has a 32-byte overhead, so subtract that first.
        self.remaining = self
            .remaining
            .checked_sub(32)
            .ok_or(Error::HeaderListTooLarge)?;

        Ok(())
    }

    /// Marks when a field part (either name or value) has been decoded.
    ///
    /// The `len` parameter is the size in bytes of the decoded part.
    ///
    /// Must be called when a new field part has been decoded.
    fn on_field_part_decoded(&mut self, len: u64) -> Result<()> {
        self.remaining = self
            .remaining
            .checked_sub(len)
            .ok_or(Error::HeaderListTooLarge)?;

        Ok(())
    }

    /// The remaining number of bytes in the tracker.
    fn left(&self) -> u64 {
        self.remaining
    }
}

/// A QPACK decoder.
///
/// netweir: with a dynamic table, filled from the peer's encoder stream,
/// and the decoder instructions acknowledging it (RFC 9204, Sections 3.2,
/// 4.3 and 4.4), sent as Chromium's QpackDecoder sends them
/// (quiche/quic/core/qpack/qpack_decoder.cc, OnDecodingCompleted): a
/// Section Acknowledgment for each field section that used the table,
/// then an Insert Count Increment for any entries still unacknowledged.
pub struct Decoder {
    table: DynamicTable,

    /// Encoder stream bytes that don't make a whole instruction yet.
    partial: Vec<u8>,

    /// Decoder instructions waiting to go out on the decoder stream.
    instructions: Vec<u8>,

    /// The insert count the encoder knows the decoder has reached.
    known_received_count: u64,
}

impl Default for Decoder {
    fn default() -> Decoder {
        Decoder::new()
    }
}

impl Decoder {
    /// Creates a new QPACK decoder, with no dynamic table.
    pub fn new() -> Decoder {
        Decoder::with_max_table_capacity(0)
    }

    /// netweir: creates a QPACK decoder whose dynamic table may grow to
    /// `max`, the SETTINGS_QPACK_MAX_TABLE_CAPACITY advertised to the peer.
    pub fn with_max_table_capacity(max: u64) -> Decoder {
        Decoder {
            table: DynamicTable::new(usize::try_from(max).unwrap_or(usize::MAX)),
            partial: Vec::new(),
            instructions: Vec::new(),
            known_received_count: 0,
        }
    }

    /// netweir: the number of entries inserted in the dynamic table so far.
    pub fn insert_count(&self) -> u64 {
        self.table.insert_count()
    }

    /// netweir: takes the decoder instructions to send on the decoder
    /// stream.
    pub fn take_instructions(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.instructions)
    }

    /// Processes control instructions from the encoder.
    ///
    /// netweir: applies them to the dynamic table. An instruction split
    /// across calls is kept until the rest arrives.
    pub fn control(&mut self, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }

        // With no table to fill, any encoder instruction is an error (RFC
        // 9204, Section 3.2.3).
        if self.table.max_capacity() == 0 {
            return Err(Error::EncoderStream);
        }

        let mut data = std::mem::take(&mut self.partial);
        data.extend_from_slice(buf);

        let mut b = octets::Octets::with_slice(&data);

        let consumed = loop {
            let at = b.off();

            if b.cap() == 0 {
                break at;
            }

            match self.instruction(&mut b) {
                Ok(()) => (),

                Err(Error::BufferTooShort) => break at,

                Err(_) => return Err(Error::EncoderStream),
            }
        };

        // Keep the unfinished instruction in place rather than copying it
        // out, so a long one arriving in small pieces isn't copied again
        // with each piece.
        data.drain(..consumed);
        self.partial = data;

        Ok(())
    }

    /// Reads one encoder instruction and applies it.
    fn instruction(&mut self, b: &mut octets::Octets) -> Result<()> {
        let first = b.peek_u8()?;
        let max = self.table.max_capacity();
        let shared = |v: Vec<u8>| -> std::sync::Arc<[u8]> { v.into() };
        let table = |r: std::result::Result<(), TableError>| {
            r.map_err(|_| Error::EncoderStream)
        };

        if first & 0x80 == 0x80 {
            // Insert with Name Reference.
            let is_static = first & 0x40 == 0x40;
            let index = decode_int(b, 6)?;
            let value = shared(encoder_str(b, 7, max)?);

            if is_static {
                table(self.table.insert_with_static_name_reference(index, value))
            } else {
                table(self.table.insert_with_dynamic_name_reference(index, value))
            }
        } else if first & 0x40 == 0x40 {
            // Insert with Literal Name.
            let name = shared(encoder_str(b, 5, max)?);
            let value = shared(encoder_str(b, 7, max)?);

            table(self.table.insert_with_literal_name(name, value))
        } else if first & 0x20 == 0x20 {
            // Set Dynamic Table Capacity.
            let capacity = decode_int(b, 5)?;

            table(self.table.set_dynamic_table_capacity(capacity))
        } else {
            // Duplicate.
            let index = decode_int(b, 5)?;

            table(self.table.duplicate(index))
        }
    }

    /// The Required Insert Count of a field section (RFC 9204, Section
    /// 4.5.1.1), read from its prefix.
    fn required_insert_count(&self, encoded: u64) -> Result<u64> {
        if encoded == 0 {
            return Ok(0);
        }

        let max_entries = self.table.max_capacity() as u64 / 32;
        let full_range = 2 * max_entries;

        if encoded > full_range {
            return Err(Error::InvalidHeaderValue);
        }

        let max_value = self.table.insert_count() + max_entries;
        let max_wrapped = (max_value / full_range) * full_range;
        let mut ric = max_wrapped + encoded - 1;

        if ric > max_value {
            if ric <= full_range {
                return Err(Error::InvalidHeaderValue);
            }

            ric -= full_range;
        }

        if ric == 0 {
            return Err(Error::InvalidHeaderValue);
        }

        Ok(ric)
    }

    /// netweir: whether the field section in `buf` needs dynamic table
    /// entries that haven't arrived yet.
    pub fn is_blocked(&self, buf: &[u8]) -> Result<bool> {
        let mut b = octets::Octets::with_slice(buf);
        let ric = self.required_insert_count(decode_int(&mut b, 8)?)?;

        Ok(ric > self.table.insert_count())
    }

    /// netweir: decodes the field section of `stream_id`, then queues the
    /// decoder instructions Chromium sends after one.
    pub fn decode_for_stream(
        &mut self, buf: &[u8], max_size: u64, stream_id: u64,
    ) -> Result<Vec<Header>> {
        let (headers, ric) = self.decode_section(buf, max_size)?;

        if ric > 0 {
            // Section Acknowledgment.
            encode_int_into(&mut self.instructions, stream_id, 0x80, 7);
            self.known_received_count = self.known_received_count.max(ric);
        }

        let inserts = self.table.insert_count();
        if self.known_received_count < inserts {
            // Insert Count Increment.
            encode_int_into(
                &mut self.instructions,
                inserts - self.known_received_count,
                0x00,
                6,
            );
            self.known_received_count = inserts;
        }

        Ok(headers)
    }

    /// Decodes a QPACK header block into a list of headers.
    pub fn decode(&mut self, buf: &[u8], max_size: u64) -> Result<Vec<Header>> {
        self.decode_section(buf, max_size).map(|(headers, _)| headers)
    }

    /// The headers of a field section, and its Required Insert Count.
    fn decode_section(
        &mut self, buf: &[u8], max_size: u64,
    ) -> Result<(Vec<Header>, u64)> {
        let mut b = octets::Octets::with_slice(buf);

        let mut out = Vec::new();

        let mut size_tracker = FieldListSizeTracker::new(max_size);

        let req_insert_count = self.required_insert_count(decode_int(&mut b, 8)?)?;

        if req_insert_count > self.table.insert_count() {
            return Err(Error::Blocked);
        }

        // Base (RFC 9204, Section 4.5.1.2).
        let sign = b.peek_u8()? & 0x80 == 0x80;
        let delta_base = decode_int(&mut b, 7)?;
        let base = if sign {
            req_insert_count
                .checked_sub(delta_base)
                .and_then(|v| v.checked_sub(1))
                .ok_or(Error::InvalidHeaderValue)?
        } else {
            req_insert_count
                .checked_add(delta_base)
                .ok_or(Error::InvalidHeaderValue)?
        };

        trace!("Header count={req_insert_count} base={base}");

        // An entry of the dynamic table this section may refer to: at or
        // above neither the Required Insert Count nor what the table holds.
        let dynamic = |absolute: Option<u64>| -> Result<(Vec<u8>, Vec<u8>)> {
            let absolute = absolute.ok_or(Error::InvalidHeaderValue)?;
            if absolute >= req_insert_count {
                return Err(Error::InvalidHeaderValue);
            }
            let entry = self
                .table
                .get_by_absolute_index(absolute)
                .ok_or(Error::InvalidHeaderValue)?;
            Ok((entry.name().to_vec(), entry.value().to_vec()))
        };

        while b.cap() > 0 {
            let first = b.peek_u8()?;

            size_tracker.on_field_start()?;

            match Representation::from_byte(first) {
                Representation::Indexed => {
                    const STATIC: u8 = 0x40;

                    let s = first & STATIC == STATIC;
                    let index = decode_int(&mut b, 6)?;

                    trace!("Indexed index={index} static={s}");

                    let (name, value) = if s {
                        let (name, value) = lookup_static(index)?;
                        (name.to_vec(), value.to_vec())
                    } else {
                        dynamic(base.checked_sub(index).and_then(|v| v.checked_sub(1)))?
                    };

                    size_tracker.on_field_part_decoded(
                        (name.len() + value.len()) as u64,
                    )?;

                    out.push(Header(name, value));
                },

                Representation::IndexedWithPostBase => {
                    let index = decode_int(&mut b, 4)?;

                    trace!("Indexed With Post Base index={index}");

                    let (name, value) = dynamic(base.checked_add(index))?;

                    size_tracker.on_field_part_decoded(
                        (name.len() + value.len()) as u64,
                    )?;

                    out.push(Header(name, value));
                },

                Representation::Literal => {
                    let name_huff = b.as_ref()[0] & 0x08 == 0x08;
                    let name_len = decode_int(&mut b, 3)? as usize;

                    let mut name = b.get_bytes(name_len)?;

                    let name = if name_huff {
                        name.get_huffman_decoded_with_max_length(
                            size_tracker.left() as usize,
                        )
                        .map_err(|_| Error::HeaderListTooLarge)?
                    } else {
                        if name_len > size_tracker.left() as usize {
                            return Err(Error::HeaderListTooLarge);
                        }
                        name.to_vec()
                    };

                    size_tracker.on_field_part_decoded(name.len() as u64)?;

                    let value = decode_str(&mut b, size_tracker.left() as usize)?;

                    trace!(
                        "Literal Without Name Reference name={name:?} value={value:?}",
                    );

                    size_tracker.on_field_part_decoded(value.len() as u64)?;

                    // Instead of calling Header::new(), create Header directly
                    // from `name` and `value`.
                    let hdr = Header(name, value);
                    out.push(hdr);
                },

                Representation::LiteralWithNameRef => {
                    const STATIC: u8 = 0x10;

                    let s = first & STATIC == STATIC;

                    let name_idx = decode_int(&mut b, 4)?;

                    let name = if s {
                        lookup_static(name_idx)?.0.to_vec()
                    } else {
                        dynamic(
                            base.checked_sub(name_idx).and_then(|v| v.checked_sub(1)),
                        )?
                        .0
                    };

                    size_tracker.on_field_part_decoded(name.len() as u64)?;

                    let value = decode_str(&mut b, size_tracker.left() as usize)?;

                    trace!(
                        "Literal name_idx={name_idx} static={s} value={value:?}"
                    );

                    size_tracker.on_field_part_decoded(value.len() as u64)?;

                    out.push(Header(name, value));
                },

                Representation::LiteralWithPostBase => {
                    trace!("Literal With Post Base");

                    let name_idx = decode_int(&mut b, 3)?;

                    let name = dynamic(base.checked_add(name_idx))?.0;

                    size_tracker.on_field_part_decoded(name.len() as u64)?;

                    let value = decode_str(&mut b, size_tracker.left() as usize)?;

                    size_tracker.on_field_part_decoded(value.len() as u64)?;

                    out.push(Header(name, value));
                },
            }
        }

        Ok((out, req_insert_count))
    }
}

/// Appends `v` to `out` as a QPACK prefixed integer (RFC 9204, Section
/// 4.1.1), with `first` holding the bits above the prefix.
fn encode_int_into(out: &mut Vec<u8>, mut v: u64, first: u8, prefix: usize) {
    let mask = (1u64 << prefix) - 1;

    if v < mask {
        out.push(first | v as u8);
        return;
    }

    out.push(first | mask as u8);
    v -= mask;

    while v >= 128 {
        out.push((v % 128) as u8 | 0x80);
        v /= 128;
    }

    out.push(v as u8);
}

fn lookup_static(idx: u64) -> Result<(&'static [u8], &'static [u8])> {
    if idx >= super::static_table::STATIC_DECODE_TABLE.len() as u64 {
        return Err(Error::InvalidStaticTableIndex);
    }

    Ok(super::static_table::STATIC_DECODE_TABLE[idx as usize])
}

fn decode_int(b: &mut octets::Octets, prefix: usize) -> Result<u64> {
    let mask = 2u64.pow(prefix as u32) - 1;

    let mut val = u64::from(b.get_u8()?);
    val &= mask;

    if val < mask {
        return Ok(val);
    }

    let mut shift = 0;

    while b.cap() > 0 {
        let byte = b.get_u8()?;

        let inc = u64::from(byte & 0x7f)
            .checked_shl(shift)
            .ok_or(Error::BufferTooShort)?;

        val = val.checked_add(inc).ok_or(Error::BufferTooShort)?;

        shift += 7;

        if byte & 0x80 == 0 {
            return Ok(val);
        }
    }

    Err(Error::BufferTooShort)
}

/// netweir: a string of an encoder instruction, its Huffman flag just above
/// its length's `prefix` bits. An entry can't be larger than the table, so
/// a declared length that couldn't fit in `max` is an error before any of
/// its bytes are waited for: a Huffman code takes at most 30 bits a byte
/// (RFC 7541, Appendix B), under 4 times the decoded length.
fn encoder_str(
    b: &mut octets::Octets, prefix: usize, max: usize,
) -> Result<Vec<u8>> {
    let huff = b.peek_u8()? & (1 << prefix) != 0;
    let len = decode_int(b, prefix)?;

    let limit = if huff { max.saturating_mul(4) } else { max };
    if len > limit as u64 {
        return Err(Error::EncoderStream);
    }

    let mut val = b.get_bytes(len as usize)?;

    if huff {
        val.get_huffman_decoded_with_max_length(max)
            .map_err(|_| Error::EncoderStream)
    } else {
        Ok(val.to_vec())
    }
}

fn decode_str(b: &mut octets::Octets, max_len: usize) -> Result<Vec<u8>> {
    let first = b.peek_u8()?;

    let huff = first & 0x80 == 0x80;

    let len = decode_int(b, 7)? as usize;

    let mut val = b.get_bytes(len)?;

    let val = if huff {
        val.get_huffman_decoded_with_max_length(max_len)
            .map_err(|_| Error::HeaderListTooLarge)?
    } else {
        if len > max_len {
            return Err(Error::HeaderListTooLarge);
        }
        val.to_vec()
    };

    Ok(val)
}

#[cfg(test)]
mod tests {
    use super::*;

    // netweir: the dynamic table, filled from the encoder stream.
    fn custom_entry_decoder() -> Decoder {
        let mut d = Decoder::with_max_table_capacity(4096);
        // Set Dynamic Table Capacity 220, then Insert with Literal Name
        // custom-key: custom-value, split across two calls.
        let mut instructions = vec![0x3f, 0xbd, 0x01, 0x4a];
        instructions.extend_from_slice(b"custom-key");
        instructions.push(0x0c);
        instructions.extend_from_slice(b"custom-value");
        let (one, two) = instructions.split_at_mut(9);
        d.control(one).unwrap();
        assert_eq!(d.insert_count(), 0);
        d.control(two).unwrap();
        assert_eq!(d.insert_count(), 1);
        d
    }

    #[test]
    fn dynamic_indexed_and_acknowledged() {
        let mut d = custom_entry_decoder();
        // Required Insert Count 1 (encoded 2 for 128 entries), Base 1,
        // Indexed dynamic relative 0, then a static :method GET.
        let block = [0x02, 0x00, 0x80, 0xd1];
        let headers = d.decode_for_stream(&block, u64::MAX, 4).unwrap();
        assert_eq!(headers, vec![
            Header::new(b"custom-key", b"custom-value"),
            Header::new(b":method", b"GET"),
        ]);
        // Section Acknowledgment for stream 4, and nothing else to count.
        assert_eq!(d.take_instructions(), vec![0x84]);
    }

    #[test]
    fn dynamic_post_base_and_name_reference() {
        let mut d = custom_entry_decoder();
        // Required Insert Count 1, Base 0 (sign set, delta 0): Indexed
        // With Post-Base 0, then Literal With Post-Base Name Reference 0.
        let block = [0x02, 0x80, 0x10, 0x00, 0x03, b'a', b'b', b'c'];
        let headers = d.decode_for_stream(&block, u64::MAX, 0).unwrap();
        assert_eq!(headers, vec![
            Header::new(b"custom-key", b"custom-value"),
            Header::new(b"custom-key", b"abc"),
        ]);
    }

    #[test]
    fn entries_not_referenced_are_counted() {
        let mut d = custom_entry_decoder();
        let headers = d.decode_for_stream(&[0x00, 0x00, 0xd1], u64::MAX, 0).unwrap();
        assert_eq!(headers, vec![Header::new(b":method", b"GET")]);
        // Insert Count Increment 1.
        assert_eq!(d.take_instructions(), vec![0x01]);
    }

    #[test]
    fn section_waits_for_its_entries() {
        let mut d = Decoder::with_max_table_capacity(4096);
        let block = [0x02, 0x00, 0x80];
        assert_eq!(d.is_blocked(&block), Ok(true));
        assert_eq!(d.decode_for_stream(&block, u64::MAX, 0), Err(Error::Blocked));
        let mut d = custom_entry_decoder();
        assert_eq!(d.is_blocked(&block), Ok(false));
        // A reference past the Required Insert Count is an error.
        assert_eq!(
            d.decode_for_stream(&[0x02, 0x00, 0x81], u64::MAX, 0),
            Err(Error::InvalidHeaderValue)
        );
    }

    #[test]
    fn instructions_without_a_table_are_errors() {
        let mut d = Decoder::new();
        assert_eq!(d.control(&mut [0x20]), Err(Error::EncoderStream));
        let mut d = Decoder::with_max_table_capacity(100);
        // Capacity above the advertised maximum.
        assert_eq!(d.control(&mut [0x3f, 0xbd, 0x01]), Err(Error::EncoderStream));
    }

    // netweir: a string longer than the table could hold is refused as
    // its length is read, not buffered while the rest is waited for.
    #[test]
    fn instruction_longer_than_the_table_is_an_error() {
        // Insert with Literal Name, a name of 2^35 bytes declared.
        let mut d = Decoder::with_max_table_capacity(4096);
        assert_eq!(
            d.control(&mut [0x5f, 0xff, 0xff, 0xff, 0xff, 0x7f]),
            Err(Error::EncoderStream)
        );

        // Insert with Name Reference to static :authority, a value of
        // 4097 bytes, and with Huffman 16385.
        let mut d = Decoder::with_max_table_capacity(4096);
        assert_eq!(
            d.control(&mut [0xc0, 0x7f, 0x82, 0x1f]),
            Err(Error::EncoderStream)
        );
        let mut d = Decoder::with_max_table_capacity(4096);
        assert_eq!(
            d.control(&mut [0xc0, 0xff, 0x82, 0x7f]),
            Err(Error::EncoderStream)
        );

        // One that could fit is waited for.
        let mut d = Decoder::with_max_table_capacity(4096);
        assert_eq!(d.control(&mut [0xc0, 0xff, 0x81, 0x7f]), Ok(()));
        assert_eq!(d.partial.len(), 4);
    }

    // netweir: an instruction arriving a byte at a time is applied, and
    // only its unfinished part is kept.
    #[test]
    fn instruction_in_single_bytes() {
        let mut d = Decoder::with_max_table_capacity(4096);
        let mut instructions = vec![0x3f, 0xbd, 0x01, 0x4a];
        instructions.extend_from_slice(b"custom-key");
        instructions.push(0x0c);
        instructions.extend_from_slice(b"custom-value");
        let mut pending = 0;
        for (i, byte) in instructions.iter().enumerate() {
            d.control(&mut [*byte]).unwrap();
            pending += 1;
            // Set Dynamic Table Capacity ends at the third byte.
            if i == 2 || i == instructions.len() - 1 {
                pending = 0;
            }
            assert_eq!(d.partial.len(), pending);
        }
        assert_eq!(d.insert_count(), 1);
        assert!(d.partial.is_empty());
    }

    #[test]
    fn decode_int1() {
        let encoded = [0b01010, 0x02];
        let mut b = octets::Octets::with_slice(&encoded);

        assert_eq!(decode_int(&mut b, 5), Ok(10));
    }

    #[test]
    fn decode_int2() {
        let encoded = [0b11111, 0b10011010, 0b00001010];
        let mut b = octets::Octets::with_slice(&encoded);

        assert_eq!(decode_int(&mut b, 5), Ok(1337));
    }

    #[test]
    fn decode_int3() {
        let encoded = [0b101010];
        let mut b = octets::Octets::with_slice(&encoded);

        assert_eq!(decode_int(&mut b, 8), Ok(42));
    }

    /// LiteralWithNameRef with the dynamic table flag (S=0) must be
    /// rejected since dynamic table references are not decoded yet.
    #[test]
    fn literal_with_name_ref_dynamic_table_rejected() {
        let mut dec = Decoder::new();

        // QPACK header block:
        //   [0x00, 0x00]  required insert count=0, base=0
        //   [0x40]        LiteralWithNameRef (0b0100_0000), S=0 (dynamic),
        //                 name_idx=0
        //   [0x01, 0x61]  value: non-huffman, length=1, 'a'
        let encoded = [0x00, 0x00, 0x40, 0x01, 0x61];

        assert_eq!(
            dec.decode(&encoded, u64::MAX),
            Err(Error::InvalidHeaderValue),
        );
    }

    /// Non-Huffman value in decode_str must be rejected before allocation
    /// when it exceeds the remaining budget (max_len).
    ///
    /// Uses a LiteralWithNameRef with static `:authority` (index 0, 10
    /// bytes) and a non-Huffman value of 5 bytes. Budget is set so only
    /// 4 bytes remain for the value after the name is charged.
    #[test]
    fn non_huffman_value_exceeding_budget_rejected() {
        // QPACK header block:
        //   [0x00, 0x00]  required insert count=0, base=0
        //   [0x50]        LiteralWithNameRef, S=1 (static), name_idx=0
        //                 (:authority, 10 bytes)
        //   [0x05]        value: non-huffman (bit 7=0), length=5
        //   "abcde"       value bytes
        let encoded = [0x00, 0x00, 0x50, 0x05, 0x61, 0x62, 0x63, 0x64, 0x65];

        // Exact fit: 32 (overhead) + 10 (name) + 5 (value) = 47.
        assert!(Decoder::new().decode(&encoded, 47).is_ok());

        // One byte too small: budget = 46.
        // After overhead (32) and name (10): 4 bytes remain, but
        // value is 5 bytes → rejected.
        assert_eq!(
            Decoder::new().decode(&encoded, 46),
            Err(Error::HeaderListTooLarge),
        );
    }

    /// Non-Huffman name in the Literal arm must be rejected before
    /// allocation when it exceeds the remaining budget.
    ///
    /// Uses a Literal with a 10-byte non-Huffman name and a 1-byte
    /// non-Huffman value. Budget is set so only 9 bytes remain for the
    /// name after overhead.
    #[test]
    fn non_huffman_name_exceeding_budget_rejected() {
        // QPACK header block:
        //   [0x00, 0x00]  required insert count=0, base=0
        //   [0x27, 0x03]  Literal (0b0010_0000), N=0, H=0 (no huffman),
        //                 name_len=10 (3-bit prefix 0b111 + overflow 0x03)
        //   "x-custom99"  name bytes (10 bytes)
        //   [0x01, 0x61]  value: non-huffman, length=1, 'a'
        let encoded = [
            0x00, 0x00, // header block prefix
            0x27, 0x03, // Literal, name_len=10
            0x78, 0x2d, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x39,
            0x39, // "x-custom99"
            0x01, 0x61, // value: length=1, 'a'
        ];

        // Exact fit: 32 (overhead) + 10 (name) + 1 (value) = 43.
        assert!(Decoder::new().decode(&encoded, 43).is_ok());

        // Two bytes too small: budget = 41.
        // After overhead (32): 9 bytes remain, name is 10 bytes →
        // rejected at name check.
        assert_eq!(
            Decoder::new().decode(&encoded, 41),
            Err(Error::HeaderListTooLarge),
        );
    }

    /// Verify that both Literal and LiteralWithNameRef charge the name to
    /// the budget *before* Huffman-decoding the value, so the max_len
    /// passed to the Huffman decoder is equally strict in both paths.
    #[test]
    fn literal_with_name_ref_value_budget_ordering() {
        use crate::h3::qpack;

        // Static table index 0 = `:authority` (10 bytes).
        // We'll encode the same value two ways:
        //   1. LiteralWithNameRef using `:authority` (encoder matches static
        //      table)
        //   2. Literal using a custom 10-byte name not in the static table
        //
        // Both have name_len=10, so budget arithmetic is comparable.
        let value = b"aaaaaaaaaaaaaaaa"; // 16 bytes; Huffman compresses to 10

        // -- Encode as LiteralWithNameRef --
        let headers_nameref = vec![Header::new(b":authority", value)];
        let mut buf = [0u8; 64];
        let mut enc = qpack::Encoder::new();
        let nameref_len = enc.encode(&headers_nameref, &mut buf).unwrap();
        let encoded_nameref = buf[..nameref_len].to_vec();

        // -- Encode as Literal (name not in static table) --
        let headers_literal = vec![Header::new(b"x-custom99", value)];
        let mut buf = [0u8; 64];
        let mut enc = qpack::Encoder::new();
        let literal_len = enc.encode(&headers_literal, &mut buf).unwrap();
        let encoded_literal = buf[..literal_len].to_vec();

        // Exact budget: 32 (overhead) + 10 (name) + 16 (value) = 58.
        // Both representations succeed.
        assert_eq!(
            Decoder::new().decode(&encoded_nameref, 58),
            Ok(headers_nameref.clone()),
        );
        assert_eq!(
            Decoder::new().decode(&encoded_literal, 58),
            Ok(headers_literal.clone()),
        );

        // One byte too small: budget = 57.
        // Total decoded field size = 10 + 16 = 26, overhead = 32,
        // so 32 + 26 = 58 > 57. Both reject with HeaderListTooLarge.
        //
        // Both paths now follow the same budget ordering:
        //   1. name charged first (10 bytes) → remaining = 15
        //   2. decode_str max_len = 15
        //   3. Huffman decode produces 16 bytes > 15 → rejected
        assert_eq!(
            Decoder::new().decode(&encoded_nameref, 57),
            Err(Error::HeaderListTooLarge),
        );
        assert_eq!(
            Decoder::new().decode(&encoded_literal, 57),
            Err(Error::HeaderListTooLarge),
        );
    }
}
