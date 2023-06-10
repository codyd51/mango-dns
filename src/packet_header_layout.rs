use crate::packet_parser::DnsPacket;
use bitvec::prelude::*;
use std::fmt::{Display, Formatter};
use std::mem;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum DnsOpcode {
    Query = 0,
    Status = 2,
    Notify = 4,
}

impl TryFrom<usize> for DnsOpcode {
    type Error = usize;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Query),
            2 => Ok(Self::Status),
            4 => Ok(Self::Notify),
            _ => Err(value),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum DnsPacketResponseCode {
    Success = 0b0000,
    NxDomain = 0b0011,
}

impl TryFrom<usize> for DnsPacketResponseCode {
    type Error = usize;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            0b0000 => Ok(Self::Success),
            0b0011 => Ok(Self::NxDomain),
            _ => Err(value),
        }
    }
}

impl Display for DnsPacketResponseCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            DnsPacketResponseCode::Success => "Success",
            DnsPacketResponseCode::NxDomain => "NxDomain",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug)]
pub(crate) struct DnsPacketHeaderRaw(pub(crate) BitArray<[u16; 6], Lsb0>);

/// Returns the number of bits in `count` u16s
fn u16s(count: usize) -> usize {
    count * 16
}

impl DnsPacketHeaderRaw {
    pub(crate) const HEADER_SIZE: usize = mem::size_of::<Self>();

    fn new() -> Self {
        Self(BitArray::new([0; 6]))
    }

    fn get_u16_at_u16_idx(&self, u16_idx: usize) -> usize {
        (self.0[u16s(u16_idx)..u16s(u16_idx + 1)].load::<u16>()).to_be() as _
    }

    fn set_u16_at_u16_idx(&mut self, u16_idx: usize, val: u16) {
        self.0[u16s(u16_idx)..u16s(u16_idx + 1)].store(val.to_be())
    }

    pub(crate) fn identifier(&self) -> usize {
        self.get_u16_at_u16_idx(0)
    }

    pub(crate) fn set_identifier(&mut self, val: u16) {
        self.set_u16_at_u16_idx(0, val)
    }

    pub(crate) fn question_record_count(&self) -> usize {
        self.get_u16_at_u16_idx(2)
    }

    pub(crate) fn set_question_record_count(&mut self, val: u16) {
        self.set_u16_at_u16_idx(2, val)
    }

    pub(crate) fn answer_record_count(&self) -> usize {
        self.get_u16_at_u16_idx(3)
    }

    pub(crate) fn set_answer_record_count(&mut self, val: u16) {
        self.set_u16_at_u16_idx(3, val)
    }

    pub(crate) fn authority_record_count(&self) -> usize {
        self.get_u16_at_u16_idx(4)
    }

    pub(crate) fn set_authority_record_count(&mut self, val: u16) {
        self.set_u16_at_u16_idx(4, val)
    }

    pub(crate) fn additional_record_count(&self) -> usize {
        self.get_u16_at_u16_idx(5)
    }

    pub(crate) fn set_additional_record_count(&mut self, val: u16) {
        self.set_u16_at_u16_idx(5, val)
    }

    fn get_packed_flag_at_flags_bit_idx(&self, packed_flags_bit_idx: usize) -> bool {
        let flags = self.get_u16_at_u16_idx(1) as u16;
        let flags_bits = flags.view_bits::<Msb0>();
        let result = flags_bits.get(packed_flags_bit_idx);
        match result {
            Some(a) => *a,
            None => panic!("Invalid bit index {packed_flags_bit_idx}"),
        }
    }

    pub(crate) fn set_packed_flag_at_flags_bit_idx(
        &mut self,
        packed_flags_bit_idx: usize,
        flag: bool,
    ) {
        let mut flags = self.get_u16_at_u16_idx(1) as u16;
        let flags_bits = flags.view_bits_mut::<Msb0>();
        flags_bits.set(packed_flags_bit_idx, flag);
        self.set_u16_at_u16_idx(1, flags);
    }

    pub(crate) fn is_response(&self) -> bool {
        self.get_packed_flag_at_flags_bit_idx(0)
    }

    pub(crate) fn set_is_response(&mut self, val: bool) {
        self.set_packed_flag_at_flags_bit_idx(0, val)
    }

    pub(crate) fn opcode(&self) -> usize {
        let flags = self.get_u16_at_u16_idx(1) as u16;
        let flags_bits = flags.view_bits::<Msb0>();
        let bits = flags_bits.get(1..5).unwrap();
        bits.load::<u16>() as usize
    }

    pub(crate) fn set_opcode(&mut self, val: u8) {
        let mut flags = self.get_u16_at_u16_idx(1) as u16;
        let mut flags_bits = flags.view_bits_mut::<Msb0>();
        flags_bits[1..5].store(val);
        self.set_u16_at_u16_idx(1, flags);
    }

    pub(crate) fn is_authoritative_answer(&self) -> bool {
        self.get_packed_flag_at_flags_bit_idx(5)
    }

    pub(crate) fn is_truncated(&self) -> bool {
        self.get_packed_flag_at_flags_bit_idx(6)
    }

    pub(crate) fn is_recursion_desired(&self) -> bool {
        self.get_packed_flag_at_flags_bit_idx(7)
    }

    pub(crate) fn set_is_recursion_desired(&mut self, val: bool) {
        self.set_packed_flag_at_flags_bit_idx(7, val)
    }

    pub(crate) fn is_recursion_available(&self) -> bool {
        self.get_packed_flag_at_flags_bit_idx(8)
    }

    pub(crate) fn set_is_recursion_available(&mut self, val: bool) {
        self.set_packed_flag_at_flags_bit_idx(8, val)
    }

    pub(crate) fn response_code(&self) -> usize {
        /*
        let packed_flags = self.packed_flags();
        let bits = packed_flags.get(12..16).unwrap();
        bits.load::<u16>() as usize
        */
        let flags = self.get_u16_at_u16_idx(1) as u16;
        let flags_bits = flags.view_bits::<Msb0>();
        let bits = flags_bits.get(12..16).unwrap();
        bits.load::<u16>() as usize
    }

    pub(crate) fn set_response_code(&mut self, val: u8) {
        let mut flags = self.get_u16_at_u16_idx(1) as u16;
        let flags_bits = flags.view_bits_mut::<Msb0>();
        flags_bits[12..16].store(val);
        self.set_u16_at_u16_idx(1, flags);
    }
}

#[cfg(test)]
mod test {
    use crate::packet_header_layout::DnsPacketHeaderRaw;
    use bitvec::prelude::*;
    use std::mem;

    fn get_u16_from_header(header: &DnsPacketHeaderRaw, word_idx: usize) -> u16 {
        let header_bytes = unsafe { header.0.into_inner().align_to::<u8>().1.to_vec() };
        let byte_idx = word_idx * mem::size_of::<u16>();
        let bytes_as_u16 =
            ((header_bytes[byte_idx] as u16) << 8) | (header_bytes[byte_idx + 1] as u16);
        bytes_as_u16
    }

    #[test]
    fn packed_header_fields() {
        let mut header = DnsPacketHeaderRaw::new();
        header.set_identifier(0x1234);
        assert_eq!(get_u16_from_header(&header, 0), 0x1234);
        assert_eq!(header.get_u16_at_u16_idx(0), 0x1234);
        assert_eq!(header.identifier(), 0x1234);

        let mut header = DnsPacketHeaderRaw::new();
        header.set_is_response(true);
        assert!(header.is_response());
        assert_eq!(get_u16_from_header(&header, 1), 0x8000);

        let mut header = DnsPacketHeaderRaw::new();
        header.set_is_recursion_desired(true);
        assert!(header.is_recursion_desired());
        assert_eq!(get_u16_from_header(&header, 1), 0x0100);

        let mut header = DnsPacketHeaderRaw::new();
        header.set_is_recursion_available(true);
        assert!(header.is_recursion_available());
        assert_eq!(get_u16_from_header(&header, 1), 0x0080);

        let mut header = DnsPacketHeaderRaw::new();
        header.set_response_code(0b11);
        assert_eq!(header.response_code(), 0b11);
        assert_eq!(get_u16_from_header(&header, 1), 0x0003);

        let mut header = DnsPacketHeaderRaw::new();
        header.set_opcode(0b1111);
        assert_eq!(header.opcode(), 0b1111);
        assert_eq!(get_u16_from_header(&header, 1), 0b111100000000000);
    }
}
