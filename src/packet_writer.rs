use crate::dns_record::{DnsPacketRecordType, DnsRecord, DnsRecordData};
use crate::packet_header::{PacketDirection, ResponseFields};
use crate::packet_header_layout::{DnsOpcode, DnsPacketHeaderRaw, DnsPacketResponseCode};
use bitvec::prelude::*;
use std::net::{Ipv4Addr, Ipv6Addr};

pub(crate) struct DnsPacketWriterParams {
    transaction_id: u16,
    opcode: DnsOpcode,
    direction: PacketDirection,
}

impl DnsPacketWriterParams {
    pub(crate) fn new(transaction_id: u16, opcode: DnsOpcode, direction: PacketDirection) -> Self {
        Self {
            transaction_id,
            opcode,
            direction,
        }
    }

    pub(crate) fn new_query_response(
        transaction_id: usize,
        response_code: DnsPacketResponseCode,
    ) -> Self {
        Self::new(
            transaction_id as _,
            DnsOpcode::Query,
            PacketDirection::Response(ResponseFields::new(true, true, response_code as _)),
        )
    }
}

pub(crate) struct DnsPacketWriter {
    output_packet: Vec<u8>,
    cursor: usize,
}

impl DnsPacketWriter {
    pub(crate) fn new() -> Self {
        Self {
            output_packet: vec![],
            cursor: 0,
        }
    }

    pub(crate) fn new_raw_header(
        params: &DnsPacketWriterParams,
        question_record_count: u16,
        answer_record_count: u16,
        authority_record_count: u16,
        additional_record_count: u16,
    ) -> DnsPacketHeaderRaw {
        let mut header = DnsPacketHeaderRaw(BitArray::new([0; 6]));
        header.set_identifier(params.transaction_id);
        header.set_is_response(matches!(params.direction, PacketDirection::Response(_)));
        header.set_opcode(params.opcode as _);
        let response_code = match params.direction {
            PacketDirection::Query => {
                // Not relevant for queries
                DnsPacketResponseCode::Success
            }
            PacketDirection::Response(fields) => fields.response_code,
        };
        header.set_response_code(response_code as _);

        header.set_question_record_count(question_record_count);
        header.set_answer_record_count(answer_record_count);
        header.set_authority_record_count(authority_record_count);
        header.set_additional_record_count(additional_record_count);

        header
    }

    pub(crate) fn new_packet_from_records(
        params: DnsPacketWriterParams,
        record_types_and_records: Vec<(DnsPacketRecordType, &DnsRecord)>,
    ) -> Vec<u8> {
        let mut question_record_count = 0;
        let mut answer_record_count = 0;
        let mut authority_record_count = 0;
        let mut additional_record_count = 0;
        for (record_type, _) in record_types_and_records.iter() {
            match record_type {
                DnsPacketRecordType::QuestionRecord => question_record_count += 1,
                DnsPacketRecordType::AnswerRecord => answer_record_count += 1,
                DnsPacketRecordType::AuthorityRecord => authority_record_count += 1,
                DnsPacketRecordType::AdditionalRecord => additional_record_count += 1,
            };
        }

        let header = Self::new_raw_header(
            &params,
            question_record_count,
            answer_record_count,
            authority_record_count,
            additional_record_count,
        );
        let mut header_bytes = unsafe { header.0.into_inner().align_to::<u8>().1.to_vec() };
        let header_bytes_len = header_bytes.len();

        let mut writer = Self {
            output_packet: Vec::new(),
            cursor: 0,
        };
        writer.output_packet.append(&mut header_bytes);
        writer.cursor += header_bytes_len;

        for (_record_type, record) in record_types_and_records.iter() {
            writer.write_record(record);
        }

        writer.output_packet
    }

    fn write_record(&mut self, record: &DnsRecord) {
        // Record name
        self.write_name(record.name.as_deref());
        // Record type
        self.write_u16(record.record_type as u16);
        // Record class
        self.write_u16(record.record_class.unwrap() as u16);

        if let Some(ttl) = record.record_ttl {
            // TTL
            self.write_u32(ttl.0 as _);
        }
        if let Some(record_data) = &record.record_data {
            match &record_data {
                DnsRecordData::A(ipv4_addr) => {
                    self.write_ipv4_addr(*ipv4_addr);
                }
                DnsRecordData::CanonicalName(fqdn) => {
                    let mut name_buffer = vec![];
                    let name_len = Self::write_name_to(Some(&fqdn.0), &mut name_buffer);
                    self.write_u16(name_len as _);
                    self.write_buf(&name_buffer);
                }
                DnsRecordData::AAAA(ipv6_addr) => {
                    self.write_ipv6_addr(*ipv6_addr);
                }
                DnsRecordData::Https(https_data) => {
                    // Write it all to a buf and get the data len
                    let mut buf = vec![];

                    Self::write_u16_to(https_data.svc_priority as _, &mut buf);
                    Self::write_name_to(https_data.target_name.as_deref(), &mut buf);
                    Self::write_u16_to(https_data.svc_param_key as _, &mut buf);

                    let mut proto_names_len = 0;
                    for proto_name in https_data.supported_protocols.iter() {
                        // 1 byte for the len
                        proto_names_len += 1;
                        proto_names_len += proto_name.as_bytes().len();
                    }
                    Self::write_u16_to(proto_names_len as _, &mut buf);

                    for proto_name in https_data.supported_protocols.iter() {
                        let proto_name_bytes = proto_name.as_bytes();
                        Self::write_u8_to(proto_name_bytes.len() as _, &mut buf);
                        Self::write_buf_to(proto_name_bytes, &mut buf);
                    }

                    self.write_u16(buf.len() as _);
                    self.write_buf(&buf);
                }
                record_type => todo!("Cannot write record type {record_type:?}"),
            }
        }
    }

    fn write_u8(&mut self, val: u8) {
        Self::write_u8_to(val, &mut self.output_packet);
        self.cursor += 1;
    }

    fn write_u8_to(val: u8, out: &mut Vec<u8>) {
        out.push(val);
    }

    fn write_u16(&mut self, val: u16) {
        self.cursor += Self::write_u16_to(val, &mut self.output_packet);
    }

    fn write_u16_to(val: u16, out: &mut Vec<u8>) -> usize {
        let mut bytes = val.to_be_bytes().to_vec();
        out.append(&mut bytes);
        bytes.len()
    }

    fn write_u32(&mut self, val: u32) {
        self.write_buf(&val.to_be_bytes())
    }

    fn write_buf(&mut self, buf: &[u8]) {
        self.cursor += Self::write_buf_to(buf, &mut self.output_packet);
    }

    fn write_buf_to(src_buf: &[u8], dest_buf: &mut Vec<u8>) -> usize {
        let count = src_buf.len();
        for &b in src_buf.iter() {
            Self::write_u8_to(b, dest_buf)
        }
        count
    }

    fn write_name(&mut self, name: Option<&str>) {
        self.cursor += Self::write_name_to(name, &mut self.output_packet);
    }

    fn write_name_to(name: Option<&str>, out: &mut Vec<u8>) -> usize {
        // Null name?
        match name {
            None => {
                // Null name
                Self::write_u8_to(0, out);
                1
            }
            Some(name) => {
                let mut len = 0;
                for label in name.split(".") {
                    // Write label length, then the label data
                    Self::write_u8_to(label.len() as _, out);
                    len += 1;
                    for ch in label.chars() {
                        Self::write_u8_to(ch as _, out);
                        len += 1;
                    }
                }
                // Null byte to terminate labels
                Self::write_u8_to('\0' as _, out);
                len += 1;
                len
            }
        }
    }

    fn write_ipv4_addr_from_u32(&mut self, addr: u32) {
        // IP address length
        self.write_u16(4);

        // IP address of the record
        self.write_u32(addr);
    }

    fn write_ipv4_addr(&mut self, addr: Ipv4Addr) {
        self.write_ipv4_addr_from_u32(addr.into())
    }

    fn write_ipv6_addr(&mut self, addr: Ipv6Addr) {
        // IP address length
        self.write_u16(16);
        self.write_buf(&addr.octets())
    }
}

#[cfg(test)]
mod test {
    use crate::dns_record::{
        DnsPacketRecordType, DnsRecord, DnsRecordClass, DnsRecordData, DnsRecordTtl, DnsRecordType,
        HttpsRecordData,
    };
    use crate::packet_header::{PacketDirection, ResponseFields};
    use crate::packet_header_layout::{DnsOpcode, DnsPacketResponseCode};
    use crate::packet_writer::{DnsPacketWriter, DnsPacketWriterParams};
    use std::net::Ipv4Addr;

    #[test]
    fn write_response() {
        let transaction_id = 0x669f;
        let ttl = 300_u32;

        let a_record = DnsRecordData::A(Ipv4Addr::new(172, 67, 189, 115));
        let answer_record = DnsRecord::new(
            Some("axleos.com"),
            DnsRecordType::A,
            Some(DnsRecordClass::Internet),
            Some(DnsRecordTtl(300)),
            Some(a_record),
        );
        let mut output_packet = DnsPacketWriter::new_packet_from_records(
            DnsPacketWriterParams::new(
                transaction_id,
                DnsOpcode::Query,
                PacketDirection::Response(ResponseFields::new(
                    true,
                    false,
                    DnsPacketResponseCode::Success,
                )),
            ),
            vec![(DnsPacketRecordType::AnswerRecord, &answer_record)],
        );
        let transaction_id_bytes = transaction_id.to_be_bytes();
        let ttl_bytes = ttl.to_be_bytes();
        assert_eq!(
            output_packet,
            vec![
                // Header
                //   Transaction ID
                transaction_id_bytes[0],
                transaction_id_bytes[1],
                //   Packed flags
                0x80,
                0x00,
                //   Other header fields
                //   Question count
                0x00,
                0x00,
                //   Answer count
                0x00,
                0x01,
                //   Authority RR count
                0x00,
                0x00,
                //   Additional RR count
                0x00,
                0x00,
                // Data
                //   'axleos'
                0x06,
                0x61,
                0x78,
                0x6c,
                0x65,
                0x6f,
                0x73,
                //   'com'
                0x03,
                0x63,
                0x6f,
                0x6d,
                //   Null byte to end labels
                0x00,
                //   Type: A
                0x00,
                0x01,
                //   Class: IN
                0x00,
                0x01,
                //   TTL: 300s
                ttl_bytes[0],
                ttl_bytes[1],
                ttl_bytes[2],
                ttl_bytes[3],
                //   Data length: 4
                0x00,
                0x04,
                //   IP address
                172,
                67,
                189,
                115,
            ]
        )
    }

    #[test]
    fn write_https_record() {
        let mut writer = DnsPacketWriter::new();
        let record = DnsRecord::new(
            Some("www.google.com"),
            DnsRecordType::Https,
            Some(DnsRecordClass::Internet),
            Some(DnsRecordTtl(21600)),
            Some(DnsRecordData::Https(HttpsRecordData::new(
                1,
                None,
                1,
                vec!["h2".to_string(), "h3".to_string()],
            ))),
        );
        writer.write_record(&record);
        assert_eq!(
            writer.output_packet,
            vec![
                0x03, 0x77, 0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f,
                0x6d, 0x00, 0x00, 0x41, 0x00, 0x01, 0x00, 0x00, 0x54, 0x60, 0x00, 0x0d, 0x00, 0x01,
                0x00, 0x00, 0x01, 0x00, 0x06, 0x02, 0x68, 0x32, 0x02, 0x68, 0x33,
            ]
        );
    }
}
