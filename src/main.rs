use std::net::UdpSocket;
use log::{debug, info};
use crate::dns_record::{DnsPacketRecordType, DnsRecord, DnsRecordClass, DnsRecordData, DnsRecordTtl, DnsRecordType};
use crate::packet_header::{DnsPacketHeader, PacketDirection, ResponseFields};
use crate::packet_header_layout::DnsOpcode;
use crate::packet_parser::read_packet_to_buffer;
use crate::packet_writer::{DnsPacketWriter, DnsPacketWriterParams};
use crate::resolver::{DnsResolver, resolve_one_record};

mod packet_parser;
mod packet_header_layout;
mod dns_record;
mod packet_writer;
mod resolver;
mod packet_header;

/// Useful for testing
fn send_one_packet(
    resolver: &DnsResolver,
    socket: &UdpSocket,
) {
    let (question, response_record_data) = resolve_one_record(&resolver, "axleos.com", DnsRecordType::AAAA);
    let response_record = DnsRecord::new(
        &question.name.clone(),
        response_record_data.clone().into(),
        DnsRecordClass::Internet,
        Some(DnsRecordTtl(300)),
        Some(response_record_data),
    );
    let params = DnsPacketWriterParams::new(
        0x1234 as u16,
        DnsOpcode::Query,
        PacketDirection::Response(
            ResponseFields::new(
                true,
                false,
                0
            )
        )
    );
    let response_packet = DnsPacketWriter::new_packet_from_records(
        params,
        vec![
            (DnsPacketRecordType::QuestionRecord, &question),
            (DnsPacketRecordType::AnswerRecord, &response_record)
        ]
    );
    let resp_addr = socket.local_addr().unwrap();
    socket.send_to(&response_packet, &resp_addr).unwrap();
}

fn generate_response_packet_from_question_and_response_record(
    question_header: &DnsPacketHeader,
    question: &DnsRecord,
    response_record_data: Option<DnsRecordData>,
) -> Vec<u8> {
    let params = DnsPacketWriterParams::new(
        question_header.identifier as u16,
        DnsOpcode::Query,
        PacketDirection::Response(
            ResponseFields::new(
                true,
                false,
                0
            )
        )
    );

    if let Some(response_record_data) = response_record_data {
        let response_record = DnsRecord::new(
            &question.name.clone(),
            response_record_data.clone().into(),
            DnsRecordClass::Internet,
            Some(DnsRecordTtl(300)),
            Some(response_record_data),
        );
        info!("\tQuestion{question} => Answer {response_record}");
        DnsPacketWriter::new_packet_from_records(
            params,
            vec![
                (DnsPacketRecordType::QuestionRecord, question),
                (DnsPacketRecordType::AnswerRecord, &response_record),
            ]
        )
    }
    else {
        info!("\tQuestion{question} => NXDOMAIN");
        DnsPacketWriter::new_packet_from_records(
            params,
            vec![(DnsPacketRecordType::QuestionRecord, question)]
        )
    }
}

fn main() -> std::io::Result<()> {
    env_logger::Builder::new().filter_level(log::LevelFilter::Info).init();

    let resolver = DnsResolver::new();
    let socket = UdpSocket::bind("127.0.0.1:53")?;

    loop {
        let mut packet_buffer = [0; 1500];
        let (src, header, mut body_parser) = read_packet_to_buffer(&socket, &mut packet_buffer);
        match header.opcode {
            DnsOpcode::Query => {
                info!("Handling DNS query ID 0x{:x}", header.identifier);
                // TODO(PT): Rename this to DnsBody/parse_body?
                let body = body_parser.parse_response(&header);
                for (i, question) in body.question_records.iter().enumerate() {
                    // Ignore questions about anything other than A/AAAA records
                    if ![DnsRecordType::A, DnsRecordType::AAAA].contains(&question.record_type) {
                        debug!("\tDropping query for unsupported record type {:?}", question.record_type);
                        continue;
                    }

                    info!("\tResolving question #{i}: {question}");
                    let response = resolver.resolve_question(question);

                    let response_packet = generate_response_packet_from_question_and_response_record(
                        &header,
                        question,
                        response
                    );

                    socket.send_to(&response_packet, &src).unwrap();
                }
            }
            _ => {
                debug!("Ignoring non-query packet");
                //todo!()
            }
        }
    }
}
