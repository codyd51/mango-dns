use crate::dns_record::{
    DnsPacketRecordType, DnsRecord, DnsRecordClass, DnsRecordData, DnsRecordTtl, DnsRecordType,
};
use crate::packet_header::DnsPacketHeader;
use crate::packet_header_layout::{DnsOpcode, DnsPacketResponseCode};
use crate::packet_parser::DnsPacketParser;
use crate::packet_writer::{DnsPacketWriter, DnsPacketWriterParams};
use crate::resolver::{resolve_one_record, DnsQuestionResolutionResult, DnsResolver};
use async_channel::Receiver;
use log::{debug, error, info};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::UdpSocket;

mod dns_record;
mod packet_header;
mod packet_header_layout;
mod packet_parser;
mod packet_writer;
mod resolver;

/// Useful for testing
async fn send_one_packet(resolver: &DnsResolver, socket: &UdpSocket) {
    let (question, response_record_data) =
        resolve_one_record(&resolver, "fake.axleos.com", DnsRecordType::AAAA);
    let raw_header = DnsPacketWriter::new_raw_header(
        &DnsPacketWriterParams::new_query_response(0x1234, DnsPacketResponseCode::NxDomain),
        1,
        0,
        0,
        0,
    );
    let header = DnsPacketHeader::from(&raw_header);
    let response = generate_response_packet_from_question_and_resolution_result(
        &header,
        &question,
        response_record_data,
    );
    let resp_addr = socket.local_addr().unwrap();
    socket.send_to(&response, &resp_addr).await.unwrap();
}

fn generate_response_packet_from_question_and_resolution_result(
    question_header: &DnsPacketHeader,
    question: &DnsRecord,
    result: DnsQuestionResolutionResult,
) -> Vec<u8> {
    match result {
        DnsQuestionResolutionResult::Answer(answer_record_data) => {
            let response_record = DnsRecord::new(
                &question.name.clone(),
                (&answer_record_data).into(),
                Some(DnsRecordClass::Internet),
                Some(DnsRecordTtl(300)),
                Some(answer_record_data),
            );
            info!("\tQuestion{question} => Answer {response_record}");
            DnsPacketWriter::new_packet_from_records(
                DnsPacketWriterParams::new_query_response(
                    question_header.identifier,
                    DnsPacketResponseCode::Success,
                ),
                vec![
                    (DnsPacketRecordType::QuestionRecord, question),
                    (DnsPacketRecordType::AnswerRecord, &response_record),
                ],
            )
        }
        failure => {
            info!("\tQuestion{question} => {failure:#?}");
            // Return NXDOMAIN for every failure type
            DnsPacketWriter::new_packet_from_records(
                DnsPacketWriterParams::new_query_response(
                    question_header.identifier,
                    DnsPacketResponseCode::NxDomain,
                ),
                vec![(DnsPacketRecordType::QuestionRecord, question)],
            )
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Error)
        .init();

    let socket = UdpSocket::bind("127.0.0.1:53").await?;

    let r = Arc::new(socket);
    let (tx, rx) = async_channel::unbounded();

    for _ in 0..8 {
        let rx_clone: Receiver<(Vec<u8>, SocketAddr)> = rx.clone();
        let socket_clone = r.clone();
        tokio::spawn(async move {
            let task_local_resolver = DnsResolver::new();
            while let Ok((bytes, addr)) = rx_clone.recv().await {
                let packet = DnsPacketParser::parse_packet_buffer(&bytes);
                let packet_header = &packet.header;
                match packet_header.opcode {
                    DnsOpcode::Query => {
                        info!("Handling DNS query ID 0x{:x}", packet_header.identifier);
                        for (i, question) in packet.question_records.iter().enumerate() {
                            //info!("\tResolving question #{i}: {question}");
                            error!("{i}: Resolve {question}");
                            let result = task_local_resolver.resolve_question(question);
                            error!("\tResult for {question}: {result:?}");

                            let response_packet =
                                generate_response_packet_from_question_and_resolution_result(
                                    &packet_header,
                                    question,
                                    result,
                                );

                            socket_clone.send_to(&response_packet, &addr).await.unwrap();
                        }
                    }
                    _ => {
                        debug!("Ignoring non-query packet");
                        //todo!()
                    }
                }
            }
        });
    }

    let mut buf = [0; DnsPacketParser::MAX_UDP_PACKET_SIZE];
    loop {
        let (len, addr) = r.recv_from(&mut buf).await?;
        //println!("{:?} bytes received from {:?}", len, addr);
        tx.send((buf[..len].to_vec(), addr)).await.unwrap();
    }
}
