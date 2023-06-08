use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::{Debug, Display, Formatter};
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener, TcpStream, UdpSocket};
use bitvec::prelude::*;
use num_traits::PrimInt;
use rand::{random, Rng};
use rand::seq::SliceRandom;

#[derive(Debug, PartialEq, Eq)]
enum DnsOpcode {
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

#[derive(Debug, Copy, Clone, PartialEq)]
enum DnsRecordType {
    A = 1,
    AAAA = 28,
    Pointer = 12,
    SVCB = 64,
    StartOfAuthority = 6,
    Https = 65,
    NameServer = 2,
    CanonicalName = 5,
    DelegationSigner = 43,
    EDNSOpt = 41,
}

impl TryFrom<usize> for DnsRecordType {
    type Error = usize;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::A),
            28 => Ok(Self::AAAA),
            12 => Ok(Self::Pointer),
            64 => Ok(Self::SVCB),
            6 => Ok(Self::StartOfAuthority),
            65 => Ok(Self::Https),
            2 => Ok(Self::NameServer),
            5 => Ok(Self::CanonicalName),
            43 => Ok(Self::DelegationSigner),
            41 => Ok(Self::EDNSOpt),
            _ => Err(value),
        }
    }
}

#[derive(Debug, Copy, Clone)]
enum DnsRecordClass {
    Internet = 1,
}

impl TryFrom<usize> for DnsRecordClass {
    type Error = usize;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Internet),
            _ => Err(value),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum DnsPacketRecordType {
    QuestionRecord,
    AnswerRecord,
    AuthorityRecord,
    AdditionalRecord,
}

#[derive(Debug, Clone, Copy)]
struct DnsRecordTtl(usize);

#[derive(Debug)]
struct DnsPacketHeaderRaw(BitArray<[u16; 6], Msb0>);

/// Returns the number of bits in `count` u16s
fn u16s(count: usize) -> usize {
    count * 16
}

impl DnsPacketHeaderRaw {
    const HEADER_SIZE: usize = mem::size_of::<Self>();

    fn get_u16_at_u16_idx(&self, u16_idx: usize) -> usize {
        (self.0[u16s(u16_idx)..u16s(u16_idx + 1)].load::<u16>()).to_be() as _
    }

    fn set_u16_at_u16_idx(&mut self, u16_idx: usize, val: u16) {
        (self.0[u16s(u16_idx)..u16s(u16_idx + 1)].store(val.to_be()))
    }

    fn identifier(&self) -> usize {
        self.get_u16_at_u16_idx(0)
    }

    fn set_identifier(&mut self, val: u16) {
        self.set_u16_at_u16_idx(0, val)
    }

    fn question_record_count(&self) -> usize {
        self.get_u16_at_u16_idx(2)
    }

    fn set_question_record_count(&mut self, val: u16) {
        self.set_u16_at_u16_idx(2, val)
    }

    fn answer_record_count(&self) -> usize {
        self.get_u16_at_u16_idx(3)
    }

    fn set_answer_record_count(&mut self, val: u16) {
        self.set_u16_at_u16_idx(3, val)
    }

    fn authority_record_count(&self) -> usize {
        self.get_u16_at_u16_idx(4)
    }

    fn set_authority_record_count(&mut self, val: u16) {
        self.set_u16_at_u16_idx(4, val)
    }

    fn additional_record_count(&self) -> usize {
        self.get_u16_at_u16_idx(5)
    }

    fn set_additional_record_count(&mut self, val: u16) {
        self.set_u16_at_u16_idx(5, val)
    }

    fn packed_flags(&self) -> BitArray<u16, Msb0> {
        let mut flags = (self.get_u16_at_u16_idx(1) as u16);
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

    fn set_packed_flag_at_flags_bit_idx(&mut self, packed_flags_bit_idx: usize, flag: bool) {
        let mut flags = (self.get_u16_at_u16_idx(1) as u16);
        flags = flags.to_le();
        let v: &mut BitSlice<u16, Msb0> = BitSlice::from_element_mut(&mut flags);
        v.set(packed_flags_bit_idx, flag);
        self.set_u16_at_u16_idx(1, flags);

        //self.packed_flags_mut().set(packed_flags_bit_idx, flag)
    }

    fn is_response(&self) -> bool {
        self.get_packed_flag_at_flags_bit_idx(0)
    }

    fn set_is_response(&mut self, val: bool) {
        self.set_packed_flag_at_flags_bit_idx(0, val)
    }

    fn opcode(&self) -> usize {
        self.packed_flags()[1..5].load()
    }

    fn set_opcode(&mut self, val: u8) {
        self.packed_flags_mut()[1..5].store(val)
    }

    fn is_authoritative_answer(&self) -> bool {
        self.get_packed_flag_at_flags_bit_idx(5)
    }

    fn is_truncated(&self) -> bool {
        self.get_packed_flag_at_flags_bit_idx(6)
    }

    fn is_recursion_desired(&self) -> bool {
        self.get_packed_flag_at_flags_bit_idx(7)
    }

    fn is_recursion_available(&self) -> bool {
        self.get_packed_flag_at_flags_bit_idx(8)
    }

    fn response_code(&self) -> usize {
        self.packed_flags()[12..].load()
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ResponseFields {
    is_authority: bool,
    is_recursion_available: bool,
    response_code: usize,
}

impl ResponseFields {
    fn new(
    is_authority: bool,
    is_recursion_available: bool,
    response_code: usize,
    ) -> Self {
        Self {
            is_authority,
            is_recursion_available,
            response_code,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum PacketDirection {
    Query,
    Response(ResponseFields),
}

#[derive(Debug)]
struct DnsPacketHeader {
    identifier: usize,
    direction: PacketDirection,
    opcode: DnsOpcode,
    is_truncated: bool,
    is_recursion_desired: bool,
    question_count: usize,
    answer_count: usize,
    authority_count: usize,
    additional_record_count: usize,
}

impl From<&DnsPacketHeaderRaw> for DnsPacketHeader {
    fn from(raw: &DnsPacketHeaderRaw) -> Self {
        Self {
            identifier: raw.identifier(),
            direction: match raw.is_response() {
                true => PacketDirection::Response(ResponseFields::new(
                    raw.is_authoritative_answer(),
                    raw.is_recursion_available(),
                    raw.response_code(),
                )),
                false => PacketDirection::Query,
            },
            opcode: DnsOpcode::try_from(raw.opcode()).unwrap_or_else(|op| panic!("Unexpected DNS opcode: {}", op)),
            is_truncated: raw.is_truncated(),
            is_recursion_desired: raw.is_recursion_desired(),
            question_count: raw.question_record_count(),
            answer_count: raw.answer_record_count(),
            authority_count: raw.authority_record_count(),
            additional_record_count: raw.additional_record_count(),
        }
    }
}

impl Display for DnsPacketHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "[DnsPacketHeader ID=0x{:0x}]", self.identifier)?;
        match &self.direction {
            PacketDirection::Query => writeln!(f, "\t[Query]")?,
            PacketDirection::Response(response_fields) => {
                writeln!(f, "{}", match response_fields.is_authority {
                    true => "\t[Authoritative]",
                    false => "\t[Non-authoritative]",
                })?;

                writeln!(f, "{}", match response_fields.is_recursion_available {
                    true => "\t[Recursive]",
                    false => "\t[Non-recursive]",
                })?;

                writeln!(f, "\t[Response code #{}]", response_fields.response_code)?;
            }
        };

        if self.is_truncated {
            writeln!(f, "\t[Truncated]")?;
        }
        if self.is_recursion_desired {
            writeln!(f, "\t[Recursion requested]")?;
        }

        if self.question_count >= 1 {
            let noun = match self.question_count {
                1 => "question",
                _ => "questions",
            };
            writeln!(f, "\t[{} {noun}] ", self.question_count)?;
        }
        if self.answer_count >= 1 {
            let noun = match self.answer_count {
                1 => "answer",
                _ => "answers",
            };
            writeln!(f, "\t[{} {noun}]", self.answer_count)?;
        }
        if self.authority_count >= 1 {
            let noun = match self.authority_count {
                1 => "authorityRR",
                _ => "authorityRRs",
            };
            writeln!(f, "\t[{} {noun}]", self.authority_count)?;
        }
        if self.additional_record_count >= 1 {
            let noun = match self.additional_record_count {
                1 => "additionalRR",
                _ => "additionalRRs",
            };
            writeln!(f, "\t[{} {noun}]", self.additional_record_count)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
struct FullyQualifiedDomainName(String);

impl Display for FullyQualifiedDomainName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "FQDN({})", self.0)
    }
}

#[derive(Debug, Clone)]
struct StartOfAuthorityRecordData {
    primary_name_server: FullyQualifiedDomainName,
    responsible_mailbox: FullyQualifiedDomainName,
    serial_number: usize,
    refresh_interval: usize,
    retry_interval: usize,
    expire_limit: usize,
    minimum_ttl: usize,
}

impl StartOfAuthorityRecordData {
    fn new(
        primary_name_server: FullyQualifiedDomainName,
        responsible_mailbox: FullyQualifiedDomainName,
        serial_number: usize,
        refresh_interval: usize,
        retry_interval: usize,
        expire_limit: usize,
        minimum_ttl: usize,
    ) -> Self {
        Self {
            primary_name_server,
            responsible_mailbox,
            serial_number,
            refresh_interval,
            retry_interval,
            expire_limit,
            minimum_ttl,
        }
    }
}

#[derive(Debug, Clone)]
enum DnsRecordData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    NameServer(FullyQualifiedDomainName),
    CanonicalName(FullyQualifiedDomainName),
    StartOfAuthority(StartOfAuthorityRecordData),
}

#[derive(Debug, Clone)]
struct DnsRecord {
    name: String,
    record_type: DnsRecordType,
    record_class: DnsRecordClass,
    // The below fields aren't valid for Question records
    record_ttl: Option<DnsRecordTtl>,
    record_data: Option<DnsRecordData>,
}

impl DnsRecord {
    fn new(
        name: &str,
        record_type: DnsRecordType,
        record_class: DnsRecordClass,
        record_ttl: Option<DnsRecordTtl>,
        record_data: Option<DnsRecordData>,
    ) -> Self {
        Self {
            name: name.to_string(),
            record_type,
            record_class,
            record_ttl,
            record_data,
        }
    }

    fn new_question(
        name: &str,
        record_type: DnsRecordType,
        record_class: DnsRecordClass,
    ) -> Self {
        Self {
            name: name.to_string(),
            record_type,
            record_class,
            record_ttl: None,
            record_data: None,
        }
    }
}

struct DnsQueryParser<'a> {
    body: &'a [u8],
    cursor: usize,
}

impl<'a> DnsQueryParser<'a> {
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

    fn parse_label_len(&mut self) -> usize {
        let mut cursor = self.cursor;
        let out = self.parse_label_len_at(&mut cursor);
        self.cursor = cursor;
        out
    }

    fn parse_label_at(&mut self, len: usize, cursor: &mut usize) -> Vec<u8> {
        let mut out = vec![0; len];
        out.copy_from_slice(&self.body[*cursor..*cursor + len]);
        *cursor += len;
        out
    }

    fn parse_label(&mut self, len: usize) -> Vec<u8> {
        let mut cursor = self.cursor;
        let out = self.parse_label_at(len, &mut cursor);
        self.cursor = cursor;
        out
    }

    fn parse_name_at(&mut self, cursor: &mut usize) -> String {
        //println!("parsing name at {}...", self.cursor);
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
                //println!("Got name from pointer: {name_from_pointer}");
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

    fn parse_question(&mut self) -> DnsRecord {
        DnsRecord::new_question(
            &self.parse_name(),
            self.parse_record_type(),
            self.parse_record_class(),
        )
    }

    fn parse_record(&mut self) -> DnsRecord {
        let name = self.parse_name();
        let record_type = self.parse_record_type();
        let record_class = self.parse_record_class();
        let ttl = self.parse_ttl();
        let data_length = self.parse_u16();
        let record_data = match record_type {
            DnsRecordType::A => {
                DnsRecordData::A(Ipv4Addr::from(self.parse_ipv4()))
            }
            DnsRecordType::AAAA => {
                DnsRecordData::AAAA(Ipv6Addr::from(self.parse_ipv6()))
            }
            DnsRecordType::NameServer => {
                DnsRecordData::NameServer(FullyQualifiedDomainName(self.parse_name()))
            }
            DnsRecordType::CanonicalName => {
                DnsRecordData::CanonicalName(FullyQualifiedDomainName(self.parse_name()))
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
            _ => todo!("{record_type:?}"),
        };
        DnsRecord::new(
            &name,
            record_type,
            record_class,
            Some(ttl),
            Some(record_data)
        )
    }

    fn parse_response(&mut self, header: &DnsPacketHeader) -> DnsResponse {
        // First, parse the questions
        let mut question_records = vec![];
        for _ in 0..header.question_count {
            let question = self.parse_question();
            question_records.push(question);
        }

        let mut answer_records = vec![];
        for _ in 0..header.answer_count {
            let answer_record = self.parse_record();
            answer_records.push(answer_record);
        }

        // Parse the authoritative records
        let mut authority_records = vec![];
        for _ in 0..header.authority_count {
            let authority_record = self.parse_record();
            authority_records.push(authority_record);
        }

        // Parse additional records
        let mut additional_records = vec![];
        for _ in 0..header.additional_record_count {
            let additional_record = self.parse_record();
            additional_records.push(additional_record);
        }

        DnsResponse::new(question_records, answer_records, authority_records, additional_records)
    }
}

struct DnsPacketWriterParams {
    transaction_id: u16,
    opcode: DnsOpcode,
    direction: PacketDirection,
}

impl DnsPacketWriterParams {
    fn new(
        transaction_id: u16,
        opcode: DnsOpcode,
        direction: PacketDirection,
    ) -> Self {
        Self {
            transaction_id,
            opcode,
            direction,
        }
    }
}

struct DnsPacketWriter {
    output_packet: Vec<u8>,
    cursor: usize,
}

impl DnsPacketWriter {
    fn new_packet_from_records(params: DnsPacketWriterParams, record_types_and_records: Vec<(DnsPacketRecordType, &DnsRecord)>) -> Vec<u8> {
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

        let mut header = DnsPacketHeaderRaw(BitArray::new([0; 6]));
        header.set_identifier(params.transaction_id);
        header.set_is_response(matches!(params.direction, PacketDirection::Response(_)));
        header.set_opcode(params.opcode as _);

        header.set_question_record_count(question_record_count);
        header.set_answer_record_count(answer_record_count);
        header.set_authority_record_count(authority_record_count);
        header.set_additional_record_count(additional_record_count);

        let mut header_bytes = unsafe { header.0.into_inner().align_to::<u8>().1.to_vec() };
        let header_bytes_len = header_bytes.len();

        let mut writer = Self {
            output_packet: Vec::new(),
            cursor: 0,
        };
        writer.output_packet.append(&mut header_bytes);
        writer.cursor += header_bytes_len;

        for (record_type, record) in record_types_and_records.iter() {
            // Record name
            writer.write_name(&record.name);
            // Record type
            writer.write_u16(record.record_type as u16);
            // Record class
            writer.write_u16(record.record_class as u16);

            if let Some(ttl) = record.record_ttl {
                // TTL
                writer.write_u32(ttl.0 as _);
            }
            if let Some(record_data) = &record.record_data {
                match &record_data {
                    DnsRecordData::A(ipv4_addr) => {
                        // Data size
                        writer.write_ipv4_addr(*ipv4_addr);
                    },
                    DnsRecordData::CanonicalName(fqdn) => {
                        todo!();
                    }
                    _ => todo!(),
                }
            }
        }

        writer.output_packet
    }
    fn write_u8(&mut self, val: u8) {
        self.output_packet.push(val);
        self.cursor += 1;
    }

    fn write_u16(&mut self, val: u16) {
        for &b in val.to_be_bytes().iter() {
            self.write_u8(b);
        }
    }

    fn write_u32(&mut self, val: u32) {
        for &b in val.to_be_bytes().iter() {
            self.write_u8(b);
        }
    }

    fn write_name(&mut self, name: &str) {
        for label in name.split(".") {
            // Write label length, then the label data
            self.write_u8(label.len() as _);
            for ch in label.chars() {
                self.write_u8(ch as _);
            }
        }
        // Null byte to terminate labels
        self.write_u8('\0' as _);

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
}

fn read_packet_to_buffer<'a>(socket: &UdpSocket, buffer: &'a mut [u8]) -> (SocketAddr, DnsPacketHeader, DnsQueryParser<'a>) {
    let (packet_size, src) = socket.recv_from(buffer).unwrap();
    let packet_data = &buffer[..packet_size];

    let (header_data, body_data) = packet_data.split_at(DnsPacketHeaderRaw::HEADER_SIZE);
    let header_raw = unsafe {
        &*(header_data.as_ptr() as *const DnsPacketHeaderRaw)
    };
    let header = DnsPacketHeader::from(header_raw);
    let body_parser = DnsQueryParser::new(body_data);
    (src, header, body_parser)
}

/// 'High-level' representation of a response from another server
#[derive(Debug)]
struct DnsResponse {
    question_records: Vec<DnsRecord>,
    answer_records: Vec<DnsRecord>,
    authority_records: Vec<DnsRecord>,
    additional_records: Vec<DnsRecord>,
}

impl DnsResponse {
    fn new(
        question_records: Vec<DnsRecord>,
        answer_records: Vec<DnsRecord>,
        authority_records: Vec<DnsRecord>,
        additional_records: Vec<DnsRecord>,
    ) -> Self {
        Self {
            question_records,
            answer_records,
            authority_records,
            additional_records,
        }
    }
}

impl Display for DnsResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        for (i, question) in self.question_records.iter().enumerate() {
            writeln!(f, "\tQuestion #{i}: {question:?}")?;
        }

        for (i, answer) in self.answer_records.iter().enumerate() {
            writeln!(f, "\tAnswer #{i}: {answer:?}")?;
        }

        for (i, authority_record) in self.authority_records.iter().enumerate() {
            writeln!(f, "\tAuthority record #{i}: {authority_record:?}")?;
        }

        for (i, additional_record) in self.additional_records.iter().enumerate() {
            writeln!(f, "\tAdditional record #{i}: {additional_record:?}")?;
        }

        Ok(())
    }
}

struct DnsResolver {
    cache: RefCell<HashMap<FullyQualifiedDomainName, Vec<DnsRecord>>>,
}

impl DnsResolver {
    const ROOT_DNS_SERVERS: [&'static str; 13] = [
        "198.41.0.4",
        "199.9.14.201",
        "192.33.4.12",
        "199.7.91.13",
        "192.203.230.10",
        "192.5.5.241",
        "192.112.36.4",
        "198.97.190.53",
        "192.36.148.17",
        "192.58.128.30",
        "193.0.14.129",
        "199.7.83.42",
        "202.12.27.33",
    ];

    fn new() -> Self {
        Self {
            cache: RefCell::new(HashMap::new()),
        }
    }

    fn dns_socket_for_ipv4(ip: Ipv4Addr) -> SocketAddr {
        format!("{ip}:53").parse().unwrap()
    }

    fn dns_socket_for_ipv6(ip: Ipv6Addr) -> SocketAddr {
        //format!("[{ip}]:53").parse().unwrap()
        format!("[{ip}]:53").parse().unwrap()
    }

    fn select_root_dns_server_socket_addr() -> SocketAddr {
        let server_ip = Self::ROOT_DNS_SERVERS.choose(&mut rand::thread_rng()).unwrap();
        Self::dns_socket_for_ipv4(server_ip.parse().unwrap())
    }

    fn await_and_parse_response(socket: &UdpSocket, transaction_id: u16) -> (DnsPacketHeader, DnsResponse) {
        // Await the response
        let mut response_buffer = [0; 1500];
        let (_src, header, mut body) = read_packet_to_buffer(&socket, &mut response_buffer);

        println!("Got response from {socket:?}:");
        println!("{header}");

        // Ensure it was the response we were expecting
        // TODO(PT): We'll need some kind of event-driven model to handle interleaved responses
        let received_transaction_id = header.identifier as u16;
        assert_eq!(received_transaction_id, transaction_id, "TODO: Received a response for a different transaction. Expected: {transaction_id}, received {received_transaction_id}");

        let response = body.parse_response(&header);
        (header, response)
    }

    fn send_question_and_await_response(&self, dest: &SocketAddr, question: &DnsRecord) -> DnsResponse {
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        // PT: For a reason I don't understand, if I try to bind directly to a root DNS server, it fails with:
        // "Can't assign requested address"
        // However, if I first bind to 0.0.0.0, then connect, it succeeds.
        println!("Connecting to: {dest:?}");
        socket.connect(dest).unwrap();

        // Send the question
        let mut rng = rand::thread_rng();
        let transaction_id = rng.gen_range(0..u16::MAX) as u16;
        let packet = DnsPacketWriter::new_packet_from_records(
            DnsPacketWriterParams::new(
                transaction_id,
                DnsOpcode::Query,
                PacketDirection::Query,
            ),
            vec![(DnsPacketRecordType::QuestionRecord, question)]
        );
        socket.send(&packet).expect("Failed to send question to {dest}");
        Self::await_and_parse_response(&socket, transaction_id).1
    }

    fn resolve_question(&self, question: &DnsRecord) -> DnsRecordData {
        // First, check whether the answer is in the cache
        {
            let mut cache = self.cache.borrow_mut();
            let requested_fqdn = FullyQualifiedDomainName(question.name.clone());
            if let Some(cached_records) = cache.get(&requested_fqdn) {
                // Pick the first cached record with a type we like
                println!("Resolving {requested_fqdn} from cache");
                return cached_records
                    .iter()
                    .find(|r| r.record_type == DnsRecordType::A)
                    .expect("Failed to find a cached A record")
                    .record_data
                    .as_ref()
                    .unwrap()
                    .clone();
            }
        }

        // Start off with querying a root DNS server
        let mut server_addr = Self::select_root_dns_server_socket_addr();

        loop {
            let response = self.send_question_and_await_response(&server_addr, question);
            println!("Response:\n{response}");

            // First, add the additional records to our cache, as we might need them to resolve the next destination
            for additional_record in response.additional_records.iter() {
                let mut cache = self.cache.borrow_mut();
                let fqdn = FullyQualifiedDomainName(additional_record.name.clone());
                cache.entry(fqdn).or_insert(vec![]).push(additional_record.clone());
            }

            // Did we receive an answer?
            if !response.answer_records.is_empty() {
                println!("Found answers!");
                // Add the answers to the cache
                for answer_record in response.answer_records.iter() {
                    let mut cache = self.cache.borrow_mut();
                    let fqdn = FullyQualifiedDomainName(answer_record.name.clone());
                    cache.entry(fqdn).or_insert(vec![]).push(answer_record.clone());
                }

                // And return the first answer
                return response
                    .answer_records[0]
                    .record_data
                    .as_ref()
                    .unwrap()
                    .clone();
            }

            // The server we just queried will tell us who the authority is for the next component of the domain name
            // Pick the first authority that the server mentioned
            let authority_record = &response.authority_records[0];

            println!("Found authority for {}: {:?}", authority_record.name, authority_record);

            match &authority_record.record_data.as_ref().unwrap() {
                DnsRecordData::NameServer(authority_name) => {
                    // (This should hit the cache, since the nameserver's A record should have been provided by the root server's additional records)
                    // TODO(PT): Explicit 'get_from_cache'
                    //let record_data = self.resolve_question(&DnsRecord::new(&authority_name.0, DnsRecordType::A, DnsRecordClass::Internet));
                    let record_data = self.resolve_question(
                        &DnsRecord::new_question(
                            &authority_name.0,
                            DnsRecordType::A,
                            DnsRecordClass::Internet,
                        )
                        //&DnsRecord::new(&authority_name.0, DnsRecordType::A, DnsRecordClass::Internet)
                    );
                    match record_data {
                        DnsRecordData::A(ipv4_addr) => {
                            server_addr = Self::dns_socket_for_ipv4(ipv4_addr);
                        }
                        DnsRecordData::AAAA(ipv6_addr) => {
                            server_addr = Self::dns_socket_for_ipv6(ipv6_addr);
                        }
                        _ => todo!(),
                    }
                }
                _ => todo!(),
            };
        }
    }
}

fn main() -> std::io::Result<()> {
    /*
    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    let dest: SocketAddr = "[2001:4860:4802:34::a]:5353".parse().unwrap();
    println!("Connecting to: {dest:?}");
    socket.connect(dest).unwrap();
    return Ok(());
     */

    let resolver = DnsResolver::new();
    /*
    let data = resolver.resolve_question(&DnsRecord::new_question(&"axleos.com", DnsRecordType::A, DnsRecordClass::Internet));
    resolver.resolve_question(&DnsRecord::new_question(&"axleos.com", DnsRecordType::A, DnsRecordClass::Internet));
    return Ok(());
     */

    // Ensure the packet header is defined correctly
    let dns_packet_header_size = mem::size_of::<DnsPacketHeaderRaw>();
    assert_eq!(dns_packet_header_size, 12);

    let socket = UdpSocket::bind("127.0.0.1:53")?;

    loop {
        let mut packet_buffer = [0; 1500];
        let (src, header, mut body_parser) = read_packet_to_buffer(&socket, &mut packet_buffer);
        match header.opcode {
            DnsOpcode::Query => {
                // Ignore
                println!("Handling DNS query");
                // TODO(PT): Rename this to DnsBody/parse_body?
                let body = body_parser.parse_response(&header);
                for (i, question) in body.question_records.iter().enumerate() {
                    // Ignore questions about anything other than A/AAAA records
                    if ![DnsRecordType::A, DnsRecordType::AAAA].contains(&question.record_type) {
                        println!("Dropping query for unsupported record type {:?}", question.record_type);
                        continue;
                    }

                    println!("\tResolving question #{i}: {question:?}");
                    let response = resolver.resolve_question(question);
                    let response_record = DnsRecord::new(
                        &question.name.clone(),
                        DnsRecordType::A,
                        DnsRecordClass::Internet,
                        Some(DnsRecordTtl(300)),
                        Some(response),
                    );
                    let params = DnsPacketWriterParams::new(
                        header.identifier as u16,
                        DnsOpcode::Query,
                        PacketDirection::Response(
                            ResponseFields::new(
                                true,
                                false,
                                0
                            )
                        )
                    );
                    let mut response_packet = DnsPacketWriter::new_packet_from_records(
                        params,
                        vec![(DnsPacketRecordType::AnswerRecord, &response_record)]
                    );
                    println!("Responding to DNS query! Answer = {response_record:?}");
                    socket.send_to(&response_packet, &src).unwrap();
                }
            }
            _ => {
                //todo!()
            }
        }
        //todo!();
    }

    Ok(())
}

#[cfg(test)]
mod test{
    use std::net::Ipv4Addr;
    use crate::{DnsOpcode, DnsPacketHeader, DnsPacketHeaderRaw, DnsPacketRecordType, DnsPacketWriter, DnsPacketWriterParams, DnsRecord, DnsRecordClass, DnsRecordData, DnsRecordTtl, DnsRecordType, PacketDirection, ResponseFields};

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
        assert_eq!(header.is_recursion_desired, true);
        assert_eq!(header.question_count, 1);
        assert_eq!(header.answer_count, 0);
        assert_eq!(header.authority_count, 0);
        assert_eq!(header.additional_record_count, 1);
    }

    #[test]
    fn write_response() {
        let transaction_id = 0x669f;
        let ttl = 300_u32;
        //let mut output_packet = DnsPacketWriter::new_answer(transaction_id, "axleos.com", ttl as _);

        let a_record = DnsRecordData::A(Ipv4Addr::new(172, 67, 189, 115));
        let answer_record = DnsRecord::new(
            &"axleos.com",
            DnsRecordType::A,
            DnsRecordClass::Internet,
            Some(DnsRecordTtl(300)),
            Some(a_record),
        );
        let mut output_packet = DnsPacketWriter::new_packet_from_records(
            DnsPacketWriterParams::new(
                transaction_id,
                DnsOpcode::Query,
                PacketDirection::Response(
                    ResponseFields::new(
                        true,
                        false,
                        0
                    )
                ),
            ),
                vec![(DnsPacketRecordType::AnswerRecord, &answer_record)]
        );
        let transaction_id_bytes = transaction_id.to_be_bytes();
        let ttl_bytes = ttl.to_be_bytes();
        assert_eq!(
            output_packet,
            vec![
                // Header
                //   Transaction ID
                transaction_id_bytes[0], transaction_id_bytes[1],
                //   Packed flags
                0x80, 0x00,
                //   Other header fields
                //   Question count
                0x00, 0x00,
                //   Answer count
                0x00, 0x01,
                //   Authority RR count
                0x00, 0x00,
                //   Additional RR count
                0x00, 0x00,
                // Data
                //   'axleos'
                0x06, 0x61, 0x78, 0x6c, 0x65, 0x6f, 0x73,
                //   'com'
                0x03, 0x63, 0x6f, 0x6d,
                //   Null byte to end labels
                0x00,
                //   Type: A
                0x00, 0x01,
                //   Class: IN
                0x00, 0x01,
                //   TTL: 300s
                ttl_bytes[0], ttl_bytes[1], ttl_bytes[2], ttl_bytes[3],
                //   Data length: 4
                0x00, 0x04,
                //   IP address
                172, 67, 189, 115,
            ]
        )
    }
}
