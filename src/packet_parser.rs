use std::{io, mem};
use std::fmt::{Display, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use bitvec::prelude::*;
use log::{debug, trace};
use crate::dns_record::{DnsPacketRecordType, DnsRecord, DnsRecordClass, DnsRecordData, DnsRecordTtl, DnsRecordType, FullyQualifiedDomainName, StartOfAuthorityRecordData};
use crate::packet_header::DnsPacketHeader;
use crate::packet_header_layout::DnsPacketHeaderRaw;


/// 'High-level' representation of a packet
#[derive(Debug)]
pub(crate) struct DnsPacket {
    pub(crate) header: DnsPacketHeader,
    pub(crate) question_records: Vec<DnsRecord>,
    pub(crate) answer_records: Vec<DnsRecord>,
    pub(crate) authority_records: Vec<DnsRecord>,
    pub(crate) additional_records: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new(
        header: DnsPacketHeader,
        question_records: Vec<DnsRecord>,
        answer_records: Vec<DnsRecord>,
        authority_records: Vec<DnsRecord>,
        additional_records: Vec<DnsRecord>,
    ) -> Self {
        Self {
            header,
            question_records,
            answer_records,
            authority_records,
            additional_records,
        }
    }
}

impl Display for DnsPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        for (i, question) in self.question_records.iter().enumerate() {
            writeln!(f, "\tQuestion #{i}: {question}")?;
        }

        for (i, answer) in self.answer_records.iter().enumerate() {
            writeln!(f, "\tAnswer #{i}: {answer}")?;
        }

        for (i, authority_record) in self.authority_records.iter().enumerate() {
            writeln!(f, "\tAuthority record #{i}: {authority_record}")?;
        }

        for (i, additional_record) in self.additional_records.iter().enumerate() {
            writeln!(f, "\tAdditional record #{i}: {additional_record}")?;
        }

        Ok(())
    }
}

pub(crate) struct DnsPacketBodyParser<'a> {
    body: &'a [u8],
    cursor: usize,
}

impl<'a> DnsPacketBodyParser<'a> {
    fn new(
        body: &'a [u8],
    ) -> Self {
        Self {
            body,
            cursor: 0,
        }
    }

    fn parse_u8_at(&self, cursor: &mut usize) -> usize {
        let val = self.body[*cursor];
        *cursor += 1;
        val as _
    }

    fn parse_u8(&mut self) -> usize {
        let mut cursor = self.cursor;
        let out = self.parse_u8_at(&mut cursor);
        self.cursor = cursor;
        out
    }

    fn parse_u16(&mut self) -> usize {
        let u16_size = mem::size_of::<u16>();
        let val = self.body[self.cursor..self.cursor + u16_size].view_bits::<Msb0>().load_be::<u16>();
        self.cursor += u16_size;
        val as _
    }

    fn parse_u32(&mut self) -> usize {
        let u32_size = mem::size_of::<u32>();
        let val = self.body[self.cursor..self.cursor + u32_size].view_bits::<Msb0>().load_be::<u32>();
        self.cursor += u32_size;
        val as _
    }

    fn parse_label_len_at(&self, cursor: &mut usize) -> usize {
        self.parse_u8_at(cursor)
    }

    fn parse_label_at(&mut self, len: usize, cursor: &mut usize) -> Vec<u8> {
        let mut out = vec![0; len];
        out.copy_from_slice(&self.body[*cursor..*cursor + len]);
        *cursor += len;
        out
    }

    fn parse_name_at(&mut self, cursor: &mut usize) -> String {
        trace!("Parsing name at {}...", self.cursor);
        // The DNS body compression scheme allows a name to be represented as:
        // - A pointer
        // - A sequence of labels ending in a pointer
        // - A sequence of labels ending in a zero byte
        let mut name_components = vec![];
        // TODO(PT): How to impose an upper limit here?
        loop {
            let label_len = self.parse_label_len_at(cursor);

            // If the high two bits of the label are set,
            // this is a pointer to a prior string
            if (label_len >> 6) == 0b11 {
                // Mask off the two high bits
                let byte1 = (label_len as u8) & !(3_u8 << 6);
                let byte2 = self.parse_u8_at(cursor) as u8;
                let label_offset_into_packet = ((byte1 as u16) << 8) | byte2 as u16;
                assert!(label_offset_into_packet as usize >= DnsPacketHeaderRaw::HEADER_SIZE, "Cannot follow pointer into packet header");

                let label_offset_into_body = label_offset_into_packet as usize - DnsPacketHeaderRaw::HEADER_SIZE;
                let mut pointer_cursor = label_offset_into_body;
                // Recurse and read a name from the pointer
                let name_from_pointer = self.parse_name_at(&mut pointer_cursor);
                debug!("Got name from pointer: {name_from_pointer}");
                name_components.push(name_from_pointer);
                // Pointers are always the end of a name
                break;
            }

            // If we're in a label list and just encountered a null byte, we're done
            if label_len == 0 {
                break;
            } else {
                // Read a label literal
                let label_bytes = self.parse_label_at(label_len, cursor);
                let label: String = label_bytes.iter().map(|&b| b as char).collect();
                name_components.push(label);
            }
        }

        name_components.join(".")
    }

    fn parse_name(&mut self) -> String {
        let mut cursor = self.cursor;
        let out = self.parse_name_at(&mut cursor);
        self.cursor = cursor;
        out
    }

    fn parse_record_type(&mut self) -> DnsRecordType {
        DnsRecordType::try_from(self.parse_u16()).unwrap_or_else(|v| panic!("{v} is not a known query type"))
    }

    fn parse_record_class(&mut self) -> DnsRecordClass {
        DnsRecordClass::try_from(self.parse_u16()).unwrap_or_else(|v| panic!("{v} is not a known query class"))
    }

    fn parse_ttl(&mut self) -> DnsRecordTtl {
        DnsRecordTtl(self.parse_u32())
    }

    fn parse_ipv4(&mut self) -> u32 {
        self.parse_u32() as _
    }

    fn parse_ipv6(&mut self) -> [u8; 16] {
        (0..16).map(|_| self.parse_u8() as u8).collect::<Vec<u8>>().try_into().unwrap()
    }

    fn parse_record(&mut self, packet_record_type: DnsPacketRecordType) -> DnsRecord {
        let name = self.parse_name();
        let record_type = self.parse_record_type();

        if record_type == DnsRecordType::EDNSOpt {
            return DnsRecord::new(
                &name,
                record_type,
                // TODO(PT): Not valid for EDNSOpt, but I'm not bothering to properly model this for now
                DnsRecordClass::Internet,
                None,
                None,
            );
        }

        let record_class = self.parse_record_class();

        // Question records stop here
        if packet_record_type == DnsPacketRecordType::QuestionRecord {
            return DnsRecord::new_question(
                &name,
                record_type,
                record_class,
            )
        }

        let ttl = self.parse_ttl();
        let data_length = self.parse_u16();
        let record_data = match record_type {
            DnsRecordType::A => {
                Some(DnsRecordData::A(Ipv4Addr::from(self.parse_ipv4())))
            }
            DnsRecordType::AAAA => {
                Some(DnsRecordData::AAAA(Ipv6Addr::from(self.parse_ipv6())))
            }
            DnsRecordType::NameServer => {
                Some(DnsRecordData::NameServer(FullyQualifiedDomainName(self.parse_name())))
            }
            DnsRecordType::CanonicalName => {
                Some(DnsRecordData::CanonicalName(FullyQualifiedDomainName(self.parse_name())))
            }
            DnsRecordType::StartOfAuthority => {
                Some(DnsRecordData::StartOfAuthority(
                    StartOfAuthorityRecordData::new(
                        FullyQualifiedDomainName(self.parse_name()),
                        FullyQualifiedDomainName(self.parse_name()),
                        self.parse_u32(),
                        self.parse_u32(),
                        self.parse_u32(),
                        self.parse_u32(),
                        self.parse_u32(),
                    )
                ))
            }
            _ => {
                // Skip past the bytes we're ignoring
                debug!("Doing stub parsing of unhandled record type {record_type:?}");
                for _ in 0..data_length {
                    self.parse_u8();
                }
                None
            },
        };
        DnsRecord::new(
            &name,
            record_type,
            record_class,
            Some(ttl),
            record_data
        )
    }
}

pub(crate) struct DnsPacketParser;

impl DnsPacketParser {
    pub(crate) const MAX_UDP_PACKET_SIZE: usize = 512;

    pub(crate) fn parse_packet_buffer(packet_buffer: &[u8]) -> DnsPacket {
        let (header_data, body_data) = packet_buffer.split_at(DnsPacketHeaderRaw::HEADER_SIZE);
        let header_raw = unsafe {
            &*(header_data.as_ptr() as *const DnsPacketHeaderRaw)
        };
        let header = DnsPacketHeader::from(header_raw);
        let mut body_parser = DnsPacketBodyParser::new(body_data);

        // First, parse the questions
        let mut question_records = vec![];
        for _ in 0..header.question_count {
            let question = body_parser.parse_record(DnsPacketRecordType::QuestionRecord);
            question_records.push(question);
        }

        let mut answer_records = vec![];
        for _ in 0..header.answer_count {
            let answer_record = body_parser.parse_record(DnsPacketRecordType::AnswerRecord);
            answer_records.push(answer_record);
        }

        // Parse the authoritative records
        let mut authority_records = vec![];
        for _ in 0..header.authority_count {
            let authority_record = body_parser.parse_record(DnsPacketRecordType::AuthorityRecord);
            authority_records.push(authority_record);
        }

        // Parse additional records
        let mut additional_records = vec![];
        for _ in 0..header.additional_record_count {
            let additional_record = body_parser.parse_record(DnsPacketRecordType::AdditionalRecord);
            additional_records.push(additional_record);
        }

        DnsPacket::new(header, question_records, answer_records, authority_records, additional_records)
    }
}

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;
    use crate::packet_header::{DnsPacketHeader, PacketDirection};
    use crate::packet_header_layout::{DnsOpcode, DnsPacketHeaderRaw};

    #[test]
    fn parse_header() {
        let header_data: [u8; 12] = [0xdc, 0xb7, 0x1, 0x20, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1];
        let header_raw = unsafe {
            &*(header_data.as_ptr() as *const DnsPacketHeaderRaw)
        };
        assert_eq!(header_raw.opcode(), 0);
        let header = DnsPacketHeader::from(header_raw);
        assert_eq!(header.identifier, 0xdcb7);
        assert_eq!(header.direction, PacketDirection::Query);
        assert_eq!(header.opcode, DnsOpcode::Query);
        assert_eq!(header.is_truncated, false);
        assert_eq!(header.is_recursion_desired, false);
        assert_eq!(header.is_recursion_available, true);
        assert_eq!(header.question_count, 1);
        assert_eq!(header.answer_count, 0);
        assert_eq!(header.authority_count, 0);
        assert_eq!(header.additional_record_count, 1);
    }
}
