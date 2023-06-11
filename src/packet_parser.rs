use crate::dns_record::{
    DelegationSignerRecordData, DnsPacketRecordType, DnsRecord, DnsRecordClass, DnsRecordData,
    DnsRecordTtl, DnsRecordType, EDNSOptRecordData, FullyQualifiedDomainName, HttpsRecordData,
    StartOfAuthorityRecordData,
};
use crate::packet_header::DnsPacketHeader;
use crate::packet_header_layout::DnsPacketHeaderRaw;
use bitvec::prelude::*;
use log::{debug, error, trace};
use std::fmt::{Display, Formatter};
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};

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
    fn new(body: &'a [u8]) -> Self {
        Self { body, cursor: 0 }
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
        let val = self.body[self.cursor..self.cursor + u16_size]
            .view_bits::<Msb0>()
            .load_be::<u16>();
        self.cursor += u16_size;
        val as _
    }

    fn parse_u32(&mut self) -> usize {
        let u32_size = mem::size_of::<u32>();
        let val = self.body[self.cursor..self.cursor + u32_size]
            .view_bits::<Msb0>()
            .load_be::<u32>();
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

    fn parse_name_at(&mut self, cursor: &mut usize) -> Option<String> {
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
                assert!(
                    label_offset_into_packet as usize >= DnsPacketHeaderRaw::HEADER_SIZE,
                    "Cannot follow pointer into packet header"
                );

                let label_offset_into_body =
                    label_offset_into_packet as usize - DnsPacketHeaderRaw::HEADER_SIZE;
                let mut pointer_cursor = label_offset_into_body;
                // Recurse and read a name from the pointer
                let name_from_pointer = self.parse_name_at(&mut pointer_cursor).unwrap();
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

        // Null name?
        if name_components.len() == 0 {
            None
        } else {
            Some(name_components.join("."))
        }
    }

    fn parse_name(&mut self) -> Option<String> {
        let mut cursor = self.cursor;
        let out = self.parse_name_at(&mut cursor);
        self.cursor = cursor;
        out
    }

    fn parse_record_type(&mut self) -> DnsRecordType {
        DnsRecordType::try_from(self.parse_u16())
            .unwrap_or_else(|v| panic!("{v} is not a known query type"))
    }

    fn parse_record_class(&mut self) -> DnsRecordClass {
        DnsRecordClass::try_from(self.parse_u16())
            .unwrap_or_else(|v| panic!("{v} is not a known query class"))
    }

    fn parse_ttl(&mut self) -> DnsRecordTtl {
        DnsRecordTtl(self.parse_u32())
    }

    fn parse_ipv4(&mut self) -> u32 {
        self.parse_u32() as _
    }

    fn parse_ipv6(&mut self) -> [u8; 16] {
        (0..16)
            .map(|_| self.parse_u8() as u8)
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap()
    }

    fn parse_bytes(&mut self, count: usize) -> Vec<u8> {
        let mut out = vec![];
        for _ in 0..count {
            out.push(self.parse_u8() as u8);
        }
        out
    }

    fn parse_record(&mut self, packet_record_type: DnsPacketRecordType) -> DnsRecord {
        let name = self.parse_name().unwrap_or_else(|| {
            panic!("Failed to find name for record type {packet_record_type:?}")
        });
        let record_type = self.parse_record_type();

        // EDNSOpt record format diverges here
        match record_type {
            DnsRecordType::EDNSOpt => {
                let udp_payload_size = self.parse_u16();
                let extended_opcode = self.parse_u8();
                let version = self.parse_u8();
                let flags = self.parse_u16();
                let options_data_len = self.parse_u16();
                let options_data = self.parse_bytes(options_data_len);
                return DnsRecord::new(
                    &name,
                    record_type,
                    None,
                    None,
                    Some(DnsRecordData::EDNSOpt(EDNSOptRecordData::new(
                        udp_payload_size,
                        extended_opcode,
                        version,
                        flags,
                        &options_data,
                    ))),
                );
            }
            _ => {} // Continue parsing down below
        }

        let record_class = self.parse_record_class();

        // Question records stop here
        if packet_record_type == DnsPacketRecordType::QuestionRecord {
            return DnsRecord::new_question(&name, record_type, record_class);
        }

        let ttl = Some(self.parse_ttl());
        let data_length = self.parse_u16();
        let record_data = match record_type {
            DnsRecordType::A => Some(DnsRecordData::A(Ipv4Addr::from(self.parse_ipv4()))),
            DnsRecordType::AAAA => Some(DnsRecordData::AAAA(Ipv6Addr::from(self.parse_ipv6()))),
            DnsRecordType::NameServer => Some(DnsRecordData::NameServer(FullyQualifiedDomainName(
                self.parse_name().unwrap(),
            ))),
            DnsRecordType::CanonicalName => Some(DnsRecordData::CanonicalName(
                FullyQualifiedDomainName(self.parse_name().unwrap()),
            )),
            DnsRecordType::StartOfAuthority => Some(DnsRecordData::StartOfAuthority(
                StartOfAuthorityRecordData::new(
                    FullyQualifiedDomainName(self.parse_name().unwrap()),
                    FullyQualifiedDomainName(self.parse_name().unwrap()),
                    self.parse_u32(),
                    self.parse_u32(),
                    self.parse_u32(),
                    self.parse_u32(),
                    self.parse_u32(),
                ),
            )),
            DnsRecordType::Pointer => Some(DnsRecordData::Pointer(FullyQualifiedDomainName(
                self.parse_name().unwrap(),
            ))),
            DnsRecordType::Https => {
                let svc_priority = self.parse_u16();
                let target_name = self.parse_name();
                let svc_param_key = self.parse_u16();
                // PT: Represents ALPN, but it's not important to model it fully yet
                assert_eq!(svc_param_key, 1);
                let svc_param_value_length = self.parse_u16();
                let mut cursor = 0;
                let mut supported_protocols = vec![];
                while cursor < svc_param_value_length {
                    let protocol_code_len = self.parse_u8();
                    cursor += mem::size_of::<u8>();
                    let protocol_code = self.parse_bytes(protocol_code_len);
                    cursor += protocol_code_len;
                    supported_protocols.push(String::from_utf8(protocol_code).unwrap());
                }
                Some(DnsRecordData::Https(HttpsRecordData::new(
                    svc_priority,
                    target_name,
                    svc_param_key,
                    supported_protocols,
                )))
            }
            DnsRecordType::DelegationSigner => {
                // Don't bother properly modelling all the semantics of these values yet
                let key_id = self.parse_u16();
                let algorithm = self.parse_u8();
                let digest_type = self.parse_u8();
                // The above parsed 4 bytes
                let digest_byte_count = data_length - 4;
                let digest = self.parse_bytes(digest_byte_count);
                Some(DnsRecordData::DelegationSigner(
                    DelegationSignerRecordData::new(key_id, algorithm, digest_type, digest),
                ))
            }
            _ => todo!("Unhandled record type {record_type:?}"),
        };
        DnsRecord::new(&name, record_type, Some(record_class), ttl, record_data)
    }
}

pub(crate) struct DnsPacketParser;

impl DnsPacketParser {
    pub(crate) const MAX_UDP_PACKET_SIZE: usize = 512;

    pub(crate) fn parse_packet_buffer(packet_buffer: &[u8]) -> DnsPacket {
        let (header_data, body_data) = packet_buffer.split_at(DnsPacketHeaderRaw::HEADER_SIZE);
        let header_raw = unsafe { &*(header_data.as_ptr() as *const DnsPacketHeaderRaw) };
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

        DnsPacket::new(
            header,
            question_records,
            answer_records,
            authority_records,
            additional_records,
        )
    }
}

#[cfg(test)]
mod test {
    use crate::dns_record::{
        DelegationSignerRecordData, DnsRecord, DnsRecordClass, DnsRecordData, DnsRecordTtl,
        DnsRecordType, EDNSOptRecordData, HttpsRecordData,
    };
    use crate::packet_header::{DnsPacketHeader, PacketDirection};
    use crate::packet_header_layout::{DnsOpcode, DnsPacketHeaderRaw};
    use crate::packet_parser::DnsPacketParser;
    use std::net::Ipv4Addr;

    #[test]
    fn parse_header() {
        let header_data: [u8; 12] = [
            0xdc, 0xb7, 0x1, 0x20, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1,
        ];
        let header_raw = unsafe { &*(header_data.as_ptr() as *const DnsPacketHeaderRaw) };
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

    #[test]
    fn parse_edns_record() {
        let packet_data = vec![
            0xcd, 0x9e, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x07, 0x70,
            0x61, 0x67, 0x65, 0x61, 0x64, 0x32, 0x11, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x73,
            0x79, 0x6e, 0x64, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x03, 0x63, 0x6f, 0x6d,
            0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];

        let result = DnsPacketParser::parse_packet_buffer(&packet_data);
        assert_eq!(result.additional_records.len(), 1);
        assert_eq!(
            result.additional_records[0],
            DnsRecord::new(
                &"",
                DnsRecordType::EDNSOpt,
                None,
                None,
                Some(DnsRecordData::EDNSOpt(EDNSOptRecordData::new(
                    4096,
                    0,
                    0,
                    0,
                    &[]
                )))
            )
        );
    }

    #[test]
    fn parse_https_record() {
        let packet_data = vec![
            0x21, 0xe9, 0x84, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77,
            0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
            0x00, 0x41, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x41, 0x00, 0x01, 0x00, 0x00, 0x54, 0x60,
            0x00, 0x0d, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x06, 0x02, 0x68, 0x32, 0x02, 0x68,
            0x33,
        ];

        let result = DnsPacketParser::parse_packet_buffer(&packet_data);
        assert_eq!(result.answer_records.len(), 1);
        assert_eq!(
            result.answer_records[0],
            DnsRecord::new(
                &"www.google.com",
                DnsRecordType::Https,
                Some(DnsRecordClass::Internet),
                Some(DnsRecordTtl(21600)),
                Some(DnsRecordData::Https(HttpsRecordData::new(
                    1,
                    None,
                    1,
                    vec!["h2".to_string(), "h3".to_string()]
                )))
            )
        );
    }

    #[test]
    fn parse_delegation_signer() {
        let packet_data = vec![
            0x24, 0x53, 0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0x6f,
            0x6e, 0x65, 0x03, 0x6f, 0x6e, 0x65, 0x03, 0x6f, 0x6e, 0x65, 0x03, 0x6f, 0x6e, 0x65,
            0x00, 0x00, 0x1c, 0x00, 0x01, 0xc0, 0x10, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x0e,
            0x10, 0x00, 0x18, 0x04, 0x6a, 0x65, 0x61, 0x6e, 0x02, 0x6e, 0x73, 0x0a, 0x63, 0x6c,
            0x6f, 0x75, 0x64, 0x66, 0x6c, 0x61, 0x72, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0xc0,
            0x10, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x07, 0x04, 0x66, 0x72,
            0x65, 0x64, 0xc0, 0x32, 0xc0, 0x10, 0x00, 0x2b, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10,
            0x00, 0x24, 0x09, 0x43, 0x0d, 0x02, 0x49, 0x9e, 0x09, 0x67, 0xfb, 0x04, 0xf5, 0x31,
            0x20, 0x4c, 0x56, 0xf6, 0xe8, 0x86, 0x3f, 0xff, 0x7c, 0xce, 0xee, 0xd1, 0x46, 0x9e,
            0x8f, 0x26, 0xd8, 0x5e, 0x2e, 0x42, 0x54, 0xdd, 0x0c, 0xbb,
        ];

        let result = DnsPacketParser::parse_packet_buffer(&packet_data);
        assert_eq!(result.authority_records.len(), 3);
        assert_eq!(
            result.authority_records[2],
            DnsRecord::new(
                &"one.one.one",
                DnsRecordType::DelegationSigner,
                Some(DnsRecordClass::Internet),
                Some(DnsRecordTtl(3600)),
                Some(DnsRecordData::DelegationSigner(
                    DelegationSignerRecordData::new(
                        0x943,
                        13,
                        2,
                        vec![
                            0x49, 0x9e, 0x09, 0x67, 0xfb, 0x04, 0xf5, 0x31, 0x20, 0x4c, 0x56, 0xf6,
                            0xe8, 0x86, 0x3f, 0xff, 0x7c, 0xce, 0xee, 0xd1, 0x46, 0x9e, 0x8f, 0x26,
                            0xd8, 0x5e, 0x2e, 0x42, 0x54, 0xdd, 0x0c, 0xbb
                        ]
                    )
                ))
            )
        );
    }
}
