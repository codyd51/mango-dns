use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use log::{debug, info};
use rand::prelude::*;
use crate::dns_record::{DnsPacketRecordType, DnsRecord, DnsRecordClass, DnsRecordData, DnsRecordType, FullyQualifiedDomainName};
use crate::packet_header::{DnsPacketHeader, PacketDirection};
use crate::packet_header_layout::DnsOpcode;
use crate::packet_parser::{DnsPacket, DnsPacketParser};
use crate::packet_writer::{DnsPacketWriter, DnsPacketWriterParams};

pub(crate) struct DnsResolver {
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

    pub(crate) fn new() -> Self {
        Self {
            cache: RefCell::new(HashMap::new()),
        }
    }

    fn dns_socket_for_ipv4(ip: Ipv4Addr) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(ip), 53)
    }

    fn dns_socket_for_ipv6(ip: Ipv6Addr) -> SocketAddr {
        SocketAddr::new(IpAddr::V6(ip), 53)
    }

    fn select_root_dns_server_socket_addr() -> SocketAddr {
        let server_ip = Self::ROOT_DNS_SERVERS.choose(&mut rand::thread_rng()).unwrap();
        Self::dns_socket_for_ipv4(server_ip.parse().unwrap())
    }

    fn await_and_parse_response(socket: &UdpSocket, transaction_id: u16) -> io::Result<DnsPacket> {
        // Await the response
        let mut response_buffer = vec![0; 1500];
        info!("Awaiting response from {socket:?} for transaction ID {transaction_id:X}");
        let (packet_size, src) = socket.recv_from(&mut response_buffer)?;
        let packet_data = &response_buffer[..packet_size];
        let packet = DnsPacketParser::parse_packet_buffer(&response_buffer);
        let packet_header = &packet.header;

        info!("Received response from {socket:?} for transaction ID {transaction_id:X}:");
        debug!("{packet_header}");

        // Ensure it was the response we were expecting
        // TODO(PT): We'll need some kind of event-driven model to handle interleaved responses
        let received_transaction_id = packet_header.identifier as u16;
        assert_eq!(received_transaction_id, transaction_id, "TODO: Received a response for a different transaction. Expected: {transaction_id}, received {received_transaction_id}");

        Ok(packet)
    }

    fn send_question_and_await_response(&self, dest: &SocketAddr, question: &DnsRecord) -> Option<DnsPacket> {
        info!("Connecting to: {dest:?}");
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
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

    fn get_record_from_cache_for_recursive_resolution(
        &self,
        fqdn: &FullyQualifiedDomainName,
    ) -> Option<DnsRecordData> {
        // PT: My ISP doesn't support IPv6, so don't try to follow AAAA records during resolution
        self.get_record_from_cache(
            fqdn,
            &[
                DnsRecordType::A,
                DnsRecordType::CanonicalName,
            ]
        )
    }

    fn get_record_from_cache_for_returning_response(
        &self,
        fqdn: &FullyQualifiedDomainName,
        requested_record_type: &DnsRecordType,
    ) -> Option<DnsRecordData> {
        self.get_record_from_cache(
            fqdn,
            &[*requested_record_type]
        )
    }

    fn get_record_from_cache(
        &self,
        fqdn: &FullyQualifiedDomainName,
        allowed_record_types: &[DnsRecordType],
    ) -> Option<DnsRecordData> {
        let cache = self.cache.borrow_mut();
        if let Some(cached_records) = cache.get(&fqdn) {
            // Pick the first cached record with a type we like
            debug!("Resolving {fqdn} from cache");

            cached_records
                .iter()
                .find(|r| {
                    allowed_record_types.contains(&r.record_type)
                })
                .map_or(
                    None,
                    |r| {
                        Some(r.record_data
                            .as_ref()
                            .unwrap()
                            .clone())
                    }
                )
        }
        else {
            None
        }
    }

    pub(crate) fn resolve_question(&self, question: &DnsRecord) -> Option<DnsRecordData> {
        // First, check whether the answer is in the cache
        let requested_fqdn = FullyQualifiedDomainName(question.name.clone());
        if let Some(cached_record) = self.get_record_from_cache_for_returning_response(&requested_fqdn, &question.record_type) {
            debug!("Serving question from cache: {requested_fqdn}");
            return Some(cached_record);
        }

        // Start off with querying a root DNS server
        let mut server_addr = Self::select_root_dns_server_socket_addr();

        loop {
            let response = self.send_question_and_await_response(&server_addr, question);
            debug!("\t\tResponse:\n{response}");

            // First, add the additional records to our cache, as we might need them to resolve the next destination
            for additional_record in response.additional_records.iter() {
                let mut cache = self.cache.borrow_mut();
                let fqdn = FullyQualifiedDomainName(additional_record.name.clone());
                cache.entry(fqdn).or_insert(vec![]).push(additional_record.clone());
            }

            // Did we receive an answer?
            if !response.answer_records.is_empty() {
                debug!("Found answers!");
                // Add the answers to the cache
                for answer_record in response.answer_records.iter() {
                    let mut cache = self.cache.borrow_mut();
                    let fqdn = FullyQualifiedDomainName(answer_record.name.clone());
                    cache.entry(fqdn).or_insert(vec![]).push(answer_record.clone());
                }

                // And return the first answer
                return Some(
                    response
                        .answer_records[0]
                        .record_data
                        .as_ref()
                        .unwrap()
                        .clone()
                );
            }

            // The server we just queried will tell us who the authority is for the next component of the domain name
            // Pick the first authority that the server mentioned
            if response.authority_records.len() == 0 {
                debug!("\t\tNo authority records returned, question: {question}, response: {response}");
                return None;
            }
            let authority_record = &response.authority_records[0];

            info!("\t\tFound authority for \"{}\": {authority_record}", authority_record.name);

            match &authority_record.record_data.as_ref().unwrap() {
                DnsRecordData::NameServer(authority_name) => {
                    // (This should hit the cache, since the nameserver's A record should have been provided by the root server's additional records)
                    debug!("\t\tAttempting to read authority info from cache for {authority_name}...");
                    let name_server_record_data = self.get_record_from_cache_for_recursive_resolution(&authority_name).unwrap_or_else(|| {
                        info!("\t\tCouldn't find info for NS {authority_name} in cache, will recurse...");
                        // TODO(PT): Handle when this fails!
                        // DnsRecord[name=partners.wg.spotify.com, A, None]
                        self.resolve_question(&DnsRecord::new_question_a(&authority_name.0)).unwrap()
                    });

                    match name_server_record_data {
                        DnsRecordData::A(ipv4_addr) => {
                            server_addr = Self::dns_socket_for_ipv4(ipv4_addr);
                        }
                        DnsRecordData::AAAA(ipv6_addr) => {
                            server_addr = Self::dns_socket_for_ipv6(ipv6_addr);
                        }
                        _ => todo!(),
                    }
                }
                DnsRecordData::StartOfAuthority(_) => {
                    // For now, treat any SOA record as meaning that the requested record doesn't exist
                    // Don't do anything with SOA records for now
                    // TODO(PT): Does this always mean that the requested record didn't exist?
                    // TODO(PT): Return a response containing the SOA, which will serve as an NXDOMAIN to the client
                    debug!("\t\tFound an SOA record, assuming this means the requested record doesn't exist...");
                    return None;
                }
                _ => todo!(),
            };
        }
    }
}

/// Useful for testing
pub(crate) fn resolve_one_record(
    resolver: &DnsResolver,
    fqdn: &str,
    record_type: DnsRecordType
) -> (DnsRecord, DnsRecordData) {
    let question = DnsRecord::new_question(
        fqdn,
        record_type,
        DnsRecordClass::Internet
    );
    let data = resolver.resolve_question(&question).unwrap();
    info!("Resolved \"{fqdn}\": {data:?}");
    (question, data)
}
