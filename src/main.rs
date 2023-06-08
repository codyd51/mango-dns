use std::fmt::{Display, Formatter};
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use bitvec::prelude::*;
use num_traits::PrimInt;

/*
# Set DNS server
networksetup -setdnsservers Wi-Fi 127.0.0.1
networksetup -setdnsservers Wi-Fi 1.1.1.1
# (Tried using the Network Configuration -> DNS menu in System Settings, but it only worked sporadically)

# Report DNS configuration
scutil --dns

# DNS code in axle looks like it already does it?

typedef struct dns_packet {
    uint16_t identifier;

    uint16_t query_response_flag:1;
    uint16_t opcode:4;
    uint16_t authoritative_answer_flag:1;
    uint16_t truncation_flag:1;
    uint16_t recursion_desired_flag:1;
    uint16_t recursion_available_flag:1;
    uint16_t zero:3;
    uint16_t response_code:4;

    uint16_t question_count;
    uint16_t answer_count;
    uint16_t authority_count;
    uint16_t additional_record_count;

    uint8_t data[];
} __attribute__((packed)) dns_packet_t;

The one in axle seems like it's nearly a DNS resolver:
- It parses traffic flowing over my local network (queries and responses)
- It can construct packets (to send queries)
- It has a cache for responding to local clients

*/

const ROOT_DNS_SERVERS: [&str; 13] = [
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

#[derive(Debug)]
enum DnsQueryType {
    A = 1,
    AAAA = 28,
    Pointer = 12,
    SVCB = 64,
    StartOfAuthority = 6,
    Https = 65,
}

impl TryFrom<usize> for DnsQueryType {
    type Error = usize;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::A),
            28 => Ok(Self::AAAA),
            12 => Ok(Self::Pointer),
            64 => Ok(Self::SVCB),
            6 => Ok(Self::StartOfAuthority),
            65 => Ok(Self::Https),
            _ => Err(value),
        }
    }
}

#[derive(Debug)]
enum DnsQueryClass {
    In = 1,
}

impl TryFrom<usize> for DnsQueryClass {
    type Error = usize;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::In),
            _ => Err(value),
        }
    }
}

#[derive(Debug)]
struct DnsPacketHeaderRaw(BitArray<[u16; 6], Msb0>);

/// Returns the number of bits in `count` u16s
fn u16s(count: usize) -> usize {
    count * 16
}

impl DnsPacketHeaderRaw {
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

    fn question_count(&self) -> usize {
        self.get_u16_at_u16_idx(2)
    }

    fn answer_count(&self) -> usize {
        self.get_u16_at_u16_idx(3)
    }

    fn set_answer_count(&mut self, val: u16) {
        self.set_u16_at_u16_idx(3, val)
    }

    fn authority_count(&self) -> usize {
        self.get_u16_at_u16_idx(4)
    }

    fn additional_record_count(&self) -> usize {
        self.get_u16_at_u16_idx(5)
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
            question_count: raw.question_count(),
            answer_count: raw.answer_count(),
            authority_count: raw.authority_count(),
            additional_record_count: raw.additional_record_count(),
        }
    }
}

impl Display for DnsPacketHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "[DnsPacketHeader 0x{:0x} ", self.identifier)?;
        match &self.direction {
            PacketDirection::Query => write!(f, "query ")?,
            PacketDirection::Response(response_fields) => {
                if !response_fields.is_authority {
                    write!(f, "non-")?;
                }
                write!(f, "authoritative ")?;

                if !response_fields.is_recursion_available {
                    write!(f, "non-")?;
                }
                write!(f, "non-recursive ")?;

                write!(f, "response (code {}) ", response_fields.response_code)?;
            }
        };

        if self.is_truncated {
            write!(f, "truncated ")?;
        }
        if self.is_recursion_desired {
            write!(f, "recursion-requested ")?;
        }

        if self.question_count >= 1 {
            let noun = match self.question_count {
                1 => "question",
                _ => "questions",
            };
            write!(f, "{} {noun} ", self.question_count)?;
        }
        if self.answer_count >= 1 {
            let noun = match self.answer_count {
                1 => "answer",
                _ => "answers",
            };
            write!(f, "{} {noun} ", self.answer_count)?;
        }
        if self.authority_count >= 1 {
            let noun = match self.authority_count {
                1 => "authorityRR",
                _ => "authorityRRs",
            };
            write!(f, "{} {noun} ", self.authority_count)?;
        }
        if self.additional_record_count >= 1 {
            let noun = match self.additional_record_count {
                1 => "additionalRR",
                _ => "additionalRRs",
            };
            write!(f, "{} {noun} ", self.additional_record_count)?;
        }

        write!(f, "]")
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

    fn parse_u16(&mut self) -> usize {
        let u16_size = mem::size_of::<u16>();
        let val = self.body[self.cursor..self.cursor + u16_size].view_bits::<Msb0>().load_be::<u16>();
        self.cursor += u16_size;
        val as _
    }

    fn parse_label_len(&mut self) -> usize {
        let label_len = self.body[self.cursor];
        self.cursor += 1;
        label_len as _
    }

    fn parse_label(&mut self, len: usize) -> Vec<u8> {
        let mut out = vec![0; len];
        out.copy_from_slice(&self.body[self.cursor..self.cursor + len]);
        self.cursor += len;
        out
    }

    fn parse_name(&mut self) -> String {
        //println!("parsing name at {}...", self.cursor);
        // The DNS body compression scheme allows a name to be represented as:
        // - A pointer
        // - A sequence of labels ending in a pointer
        // - A sequence of labels ending in a zero byte
        let mut name_components = vec![];
        // TODO(PT): How to impose an upper limit here?
        loop {
            let label_len = self.parse_label_len();

            // If the high two bits of the label are set,
            // this is a pointer to a prior string
            if (label_len >> 6) == 0b11 {
                println!("found a pointer to a prior string");
                todo!();
            }

            // If we're in a label list and just encountered a null byte, we're done
            if label_len == 0 {
                break;
            }
            else {
                // Read a label literal
                //println!("reading label literal, len={label_len}");
                let label_bytes = self.parse_label(label_len);
                let label: String = label_bytes.iter().map(|&b| b as char).collect();
                //println!("got label: {label}");
                name_components.push(label);
            }
        }

        name_components.join(".")
    }

    fn parse_query_type(&mut self) -> DnsQueryType {
        DnsQueryType::try_from(self.parse_u16()).unwrap_or_else(|v| panic!("{v} is not a known query type"))
    }

    fn parse_query_class(&mut self) -> DnsQueryClass {
        DnsQueryClass::try_from(self.parse_u16()).unwrap_or_else(|v| panic!("{v} is not a known query class"))
    }
}

struct DnsQueryWriter {
    output_packet: Vec<u8>,
    cursor: usize,
    ttl: usize,
}

impl DnsQueryWriter {
    fn new_answer(transaction_id: u16, ttl: usize) -> Self {
        let mut out = Self {
            output_packet: Vec::new(),
            cursor: 0,
            ttl,
        };
        let mut header = DnsPacketHeaderRaw(BitArray::new([0; 6]));
        header.set_identifier(transaction_id);
        header.set_is_response(true);
        header.set_opcode(0);
        header.set_answer_count(1);
        let mut header_bytes = unsafe { header.0.into_inner().align_to::<u8>().1.to_vec() };
        let header_bytes_len = header_bytes.len();
        out.output_packet.append(&mut header_bytes);
        out.cursor += header_bytes_len;
        out
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

    fn read<'a, T: BitStore, O: BitOrder>(s: &mut &'a BitSlice<T, O>, n: usize) -> &'a BitSlice<T, O> {
        let result = &s[..n];
        *s = &s[n..];
        result
    }

    fn write(&mut self) {
        let domain = "axleos.com";
        for label in domain.split(".") {
            // Write label length, then the label data
            self.write_u8(label.len() as _);
            for ch in label.chars() {
                self.write_u8(ch as _);
            }
        }
        // Null byte to terminate labels
        self.write_u8('\0' as _);

        // Type: A
        self.write_u16(1);

        // Class: IN
        self.write_u16(1);

        // TTL
        self.write_u32(self.ttl as _);

        // IP address length
        self.write_u16(4);

        // IP address of the record
        self.write_u32(0xac_43_bd_73);
    }
}

fn main() -> std::io::Result<()> {
    let root_dns_server_socket = UdpSocket::bind("0.0.0.0:53").unwrap();
    // TODO(PT): Pick a random root server
    let remote_addr: SocketAddr = format!("{}:53", ROOT_DNS_SERVERS[0]).parse().unwrap();
    root_dns_server_socket.connect(remote_addr).unwrap();
    println!("Connection to root DNS server: {root_dns_server_socket:?}");

    let mut writer = DnsQueryWriter::new_answer(0x669f, 300);
    writer.write();
    println!("{:02X?}", writer.output_packet);
    //return Ok(());

    // Ensure the packet header is defined correctly
    let dns_packet_header_size = mem::size_of::<DnsPacketHeaderRaw>();
    assert_eq!(dns_packet_header_size, 12);

    let test_packets = [
        vec![146, 156, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 2, 100, 98, 7, 95, 100, 110, 115, 45, 115, 100, 4, 95, 117, 100, 112, 5, 99, 97, 98, 108, 101, 7, 118, 105, 114, 103, 105, 110, 109, 3, 110, 101, 116, 0, 0, 12, 0, 1],
        vec![20, 88, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 119, 119, 119, 5, 97, 112, 112, 108, 101, 3, 99, 111, 109, 0, 0, 28, 0, 1],
        vec![69, 18, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 6, 115, 101, 110, 116, 114, 121, 2, 105, 111, 0, 0, 28, 0, 1],
        vec![75, 185, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 119, 119, 119, 7, 115, 112, 111, 116, 105, 102, 121, 3, 99, 111, 109, 0, 0, 28, 0, 1],
        vec![17, 197, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 11, 97, 110, 110, 111, 116, 97, 116, 105, 111, 110, 115, 6, 107, 97, 112, 101, 108, 105, 3, 99, 111, 109, 0, 0, 28, 0, 1],
    ];

    let socket = UdpSocket::bind("127.0.0.1:53")?;

    // Receives a single datagram message on the socket. If `buf` is too small to hold
    // the message, it will be cut off.
    // Set the buffer size to the MTU so we won't truncate packets
    let mut packet_buffer = [0; 1500];
    let mut i = 0;
    loop {
        /*
        let test_packet = &test_packets[i];
        i += 1;
        if i >= test_packets.len() {
            break;
        }
        let packet_size = test_packet.len();
        packet_buffer[..test_packet.len()].copy_from_slice(test_packet);
         */
        let (packet_size, src) = socket.recv_from(&mut packet_buffer)?;

        /*
        let mut writer = DnsQueryWriter::new_answer(0x669f, 300);
        writer.write();
        println!("{:02X?}", writer.output_packet);
        socket.send_to(&writer.output_packet, &src).unwrap();
        return Ok(());
        */

        let packet_data = &packet_buffer[..packet_size];
        //println!("packet data {packet_data:?}");

        let header_data = &packet_data[..dns_packet_header_size];
        let header_raw = unsafe {
            &*(header_data.as_ptr() as *const DnsPacketHeaderRaw)
        };
        let header = DnsPacketHeader::from(header_raw);
        println!("{header}");
        /*
        println!("header bytes: {header_data:?}");
        for b in header_data.iter() {
            print!("{b:#02x}, ");
        }
        println!();
        */

        let body = &packet_data[dns_packet_header_size..];
        //println!("packet body {body:?} opcode {:?}", header.opcode);
        let mut body_parser = DnsQueryParser::new(body);
        match header.opcode {
            DnsOpcode::Query => {
                println!("Handling DNS query");
                for i in 0..header.question_count {
                    println!("Handling question #{i}");
                    /*
                    let name = parse_name(body, &mut cursor);
                    println!("Got name: {name}");
                    let question_type = parse_u16(body, &mut cursor);
                    let question_class = parse_u16(body, &mut cursor);
                    println!("Question type {question_type} class {question_class}");
                    */
                    let name = body_parser.parse_name();
                    println!("\tQuestion #{i}");
                    println!("\t\t{name}");
                    let question_type = body_parser.parse_query_type();
                    let question_class = body_parser.parse_query_class();
                    println!("\t\t{question_type:?}");
                    println!("\t\t{question_class:?}");

                    if name == "axleos.com" {
                        println!("Handling query for axleos.com");

                        let mut writer = DnsQueryWriter::new_question(header.identifier as u16);
                        writer.write();

                        let mut writer = DnsQueryWriter::new_answer(header.identifier as u16, 300);
                        writer.write();
                        println!("Sending response packet data: {:02X?}", writer.output_packet);
                        socket.send_to(&writer.output_packet, &src).unwrap();
                    }
                }
                /*
                if header.answer_count > 0 || header.authority_count > 0 || header.additional_record_count > 0 {
                    todo!()
                }
                */
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
    use crate::{DnsOpcode, DnsPacketHeader, DnsPacketHeaderRaw, DnsQueryWriter, PacketDirection};

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
        let mut writer = DnsQueryWriter::new_answer(transaction_id, ttl as _);
        writer.write();
        let transaction_id_bytes = transaction_id.to_be_bytes();
        let ttl_bytes = ttl.to_be_bytes();
        assert_eq!(
            writer.output_packet,
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
