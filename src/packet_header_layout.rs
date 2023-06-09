use std::mem;
use bitvec::prelude::*;

#[derive(Debug, PartialEq, Eq)]
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

#[derive(Debug)]
pub(crate) struct DnsPacketHeaderRaw(pub(crate) BitArray<[u16; 6], Msb0>);

/// Returns the number of bits in `count` u16s
fn u16s(count: usize) -> usize {
    count * 16
}

impl DnsPacketHeaderRaw {
    pub(crate) const HEADER_SIZE: usize = mem::size_of::<Self>();

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

    fn packed_flags(&self) -> BitArray<u16, Msb0> {
        let mut flags = self.get_u16_at_u16_idx(1) as u16;
        flags = flags.to_le();
        BitArray::from(flags)
    }

    fn packed_flags_mut(&mut self) -> &mut BitSlice<u16, Msb0> {
        &mut self.0[u16s(1)..u16s(2)]
    }

    fn get_packed_flag_at_flags_bit_idx(&self, packed_flags_bit_idx: usize) -> bool {
        self.packed_flags()[packed_flags_bit_idx..packed_flags_bit_idx + 1].load::<u8>() == 1
        //self.packed_flags().get(packed_flags_bit_idx).unwrap()
    }

    pub(crate) fn set_packed_flag_at_flags_bit_idx(&mut self, packed_flags_bit_idx: usize, flag: bool) {
        let mut flags = self.get_u16_at_u16_idx(1) as u16;
        flags = flags.to_le();
        let v: &mut BitSlice<u16, Msb0> = BitSlice::from_element_mut(&mut flags);
        v.set(packed_flags_bit_idx, flag);
        self.set_u16_at_u16_idx(1, flags);

        //self.packed_flags_mut().set(packed_flags_bit_idx, flag)
    }

    pub(crate) fn is_response(&self) -> bool {
        self.get_packed_flag_at_flags_bit_idx(0)
    }

    pub(crate) fn set_is_response(&mut self, val: bool) {
        self.set_packed_flag_at_flags_bit_idx(0, val)
    }

    pub(crate) fn opcode(&self) -> usize {
        self.packed_flags()[1..5].load()
    }

    pub(crate) fn set_opcode(&mut self, val: u8) {
        self.packed_flags_mut()[1..5].store(val)
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

    pub(crate) fn is_recursion_available(&self) -> bool {
        self.get_packed_flag_at_flags_bit_idx(8)
    }

    pub(crate) fn response_code(&self) -> usize {
        self.packed_flags()[12..].load()
    }
}
