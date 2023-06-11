use crate::dns_record::{
    DnsPacketRecordType, DnsRecord, DnsRecordClass, DnsRecordData, DnsRecordType,
    FullyQualifiedDomainName,
};
use crate::packet_header::PacketDirection;
use crate::packet_header_layout::{DnsOpcode, DnsPacketResponseCode};
use crate::packet_parser::{DnsPacket, DnsPacketParser};
use crate::packet_writer::{DnsPacketWriter, DnsPacketWriterParams};
use log::{debug, error, info};
use rand::prelude::*;
use std::cell::RefCell;
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;
use std::{io, thread};

#[derive(Debug)]
pub(crate) enum DnsQuestionResolutionResult {
    CannotResolveRecordType,
    CannotReachIntermediaryServer,
    CannotIdentifyIntermediaryServer,
    NoDomain,
    Answer(DnsRecordData),
}

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

    const SUPPORTED_RECORD_TYPES_FOR_RESOLUTION: [DnsRecordType; 4] = [
        DnsRecordType::A,
        DnsRecordType::AAAA,
        DnsRecordType::Pointer,
        DnsRecordType::Https,
    ];

    pub(crate) fn new() -> Self {
        Self {
            cache: RefCell::new(HashMap::new()),
        }
    }

    fn dns_socket_for_ipv4(ip: Ipv4Addr) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(ip), 53)
    }

    fn select_root_dns_server_socket_addr() -> SocketAddr {
        let server_ip = Self::ROOT_DNS_SERVERS.choose(&mut thread_rng()).unwrap();
        Self::dns_socket_for_ipv4(server_ip.parse().unwrap())
    }

    fn await_and_parse_response(socket: &UdpSocket, transaction_id: u16) -> io::Result<DnsPacket> {
        // Await the response
        let mut response_buffer = vec![0; 1500];
        info!("Awaiting response from {socket:?} for transaction ID {transaction_id:X}");
        let (packet_size, _) = socket.recv_from(&mut response_buffer)?;
        let packet_data = &response_buffer[..packet_size];
        let packet = DnsPacketParser::parse_packet_buffer(&packet_data);
        let packet_header = &packet.header;

        info!("Received response from {socket:?} for transaction ID {transaction_id:X}:");
        debug!("{packet_header}");

        // Ensure it was the response we were expecting
        // TODO(PT): We'll need some kind of event-driven model to handle interleaved responses
        let received_transaction_id = packet_header.identifier as u16;
        assert_eq!(received_transaction_id, transaction_id, "TODO: Received a response for a different transaction. Expected: {transaction_id}, received {received_transaction_id}");

        Ok(packet)
    }

    fn send_question_and_await_response(
        &self,
        dest: &SocketAddr,
        question: &DnsRecord,
    ) -> Option<DnsPacket> {
        info!("Connecting to: {dest:?}");
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        socket.connect(dest).unwrap();

        // Send the question
        let mut rng = thread_rng();
        let transaction_id = rng.gen_range(0..u16::MAX) as u16;
        let packet = DnsPacketWriter::new_packet_from_records(
            DnsPacketWriterParams::new(transaction_id, DnsOpcode::Query, PacketDirection::Query),
            vec![(DnsPacketRecordType::QuestionRecord, question)],
        );
        debug!("Sending to {socket:?}...");
        socket
            .send(&packet)
            .unwrap_or_else(|_| panic!("Failed to send question to {dest}"));

        for attempt in 0..3 {
            let response = Self::await_and_parse_response(&socket, transaction_id);
            match response {
                Ok(packet) => return Some(packet),
                Err(ref err) => {
                    info!("Error reading from the socket: {}", err.kind());
                    thread::sleep(Duration::from_millis(100 * (attempt + 1)));
                    info!("Slept, will try again");
                }
            }
        }
        error!("Out of attempts, will return None");
        None
    }

    fn get_record_from_cache_for_recursive_resolution(
        &self,
        fqdn: &FullyQualifiedDomainName,
    ) -> Option<DnsRecordData> {
        // PT: My ISP doesn't support IPv6, so don't try to follow AAAA records during resolution
        self.get_record_from_cache(fqdn, &[DnsRecordType::A, DnsRecordType::CanonicalName])
    }

    fn get_record_from_cache_for_returning_response(
        &self,
        fqdn: &FullyQualifiedDomainName,
        requested_record_type: &DnsRecordType,
    ) -> Option<DnsRecordData> {
        self.get_record_from_cache(fqdn, &[*requested_record_type])
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
                .find(|r| allowed_record_types.contains(&r.record_type))
                .map_or(None, |r| Some(r.record_data.as_ref().unwrap().clone()))
        } else {
            None
        }
    }

    fn add_records_to_cache(&self, records: &[DnsRecord]) {
        let mut cache = self.cache.borrow_mut();
        for record in records.iter() {
            let fqdn = FullyQualifiedDomainName(record.name.clone());
            cache.entry(fqdn).or_insert(vec![]).push(record.clone());
        }
    }

    fn is_record_type_supported_for_resolution(record_type: &DnsRecordType) -> bool {
        Self::SUPPORTED_RECORD_TYPES_FOR_RESOLUTION.contains(record_type)
    }

    pub(crate) fn resolve_question(&self, question: &DnsRecord) -> DnsQuestionResolutionResult {
        // First, check whether we support resolving this record type
        if !Self::is_record_type_supported_for_resolution(&question.record_type) {
            debug!(
                "\tDropping query for unsupported record type {:?}",
                question.record_type
            );
            return DnsQuestionResolutionResult::CannotResolveRecordType;
        }

        // Then, check whether the answer is already in the cache
        let requested_fqdn = FullyQualifiedDomainName(question.name.clone());
        if let Some(cached_record) = self
            .get_record_from_cache_for_returning_response(&requested_fqdn, &question.record_type)
        {
            debug!("Serving question from cache: {requested_fqdn}");
            return DnsQuestionResolutionResult::Answer(cached_record);
        }

        // Start off with querying a root DNS server
        let mut server_addr = Self::select_root_dns_server_socket_addr();

        loop {
            let response = self.send_question_and_await_response(&server_addr, question);
            if let None = response {
                info!("Failed to find response, so will send NXDOMAIN");
                return DnsQuestionResolutionResult::CannotReachIntermediaryServer;
            }
            let response = response.unwrap();
            info!("\t\tResponse:\n{response}");

            // First, add the additional records to our cache, as we might need them to resolve the next destination
            self.add_records_to_cache(&response.additional_records);
            // Cache any answers we received too
            self.add_records_to_cache(&response.answer_records);

            if !response.answer_records.is_empty() {
                // Return the first answer
                // TODO(PT): We could return all answer records
                debug!("\t\tFound answer records! {:#?}", response.answer_records);
                return DnsQuestionResolutionResult::Answer(
                    response.answer_records[0]
                        .record_data
                        .as_ref()
                        .unwrap()
                        .clone(),
                );
            }

            if response.header.response_code == DnsPacketResponseCode::NxDomain {
                error!("Header said NXDomain! {response}");
                return DnsQuestionResolutionResult::NoDomain;
            }

            // The server we just queried will tell us who the authority is for the next component of the domain name
            // Pick the first authority that the server mentioned
            if response.authority_records.len() == 0 {
                debug!(
                    "\t\tNo authority records returned, question: {question}, response: {response}"
                );
                return DnsQuestionResolutionResult::CannotIdentifyIntermediaryServer;
            }

            let authority_nameservers =
                Self::get_nameserver_names_from_records(&response.authority_records);
            match self.select_and_resolve_nameserver_from_pool(authority_nameservers) {
                DnsQuestionResolutionResult::Answer(ns_record_data) => match ns_record_data {
                    DnsRecordData::A(ipv4_addr) => {
                        server_addr = Self::dns_socket_for_ipv4(ipv4_addr);
                    }
                    _ => panic!("We can only resolve nameservers via A records for now"),
                },
                failure => {
                    // Failed to resolve a nameserver for the provided query
                    info!("Failed to connect to a nameserver to resolve question {question}: {failure:?}");
                    return failure;
                }
            }
        }
    }

    fn get_nameserver_names_from_records(records: &[DnsRecord]) -> Vec<FullyQualifiedDomainName> {
        records
            .iter()
            .filter_map(|record| match record.record_data.as_ref() {
                Some(record_data) => match record_data {
                    DnsRecordData::NameServer(ns_name) => Some(ns_name.clone()),
                    _ => None,
                },
                None => None,
            })
            .collect()
    }

    fn select_and_resolve_nameserver_from_pool(
        &self,
        nameservers: Vec<FullyQualifiedDomainName>,
    ) -> DnsQuestionResolutionResult {
        // First, check whether any NS is already in the cache
        for nameserver in nameservers.iter() {
            debug!("\t\tAttempting to read info from cache for nameserver {nameserver}...");
            if let Some(name_server_record_data) =
                self.get_record_from_cache_for_recursive_resolution(&nameserver)
            {
                info!("\t\tResolved NS {nameserver} from cache: {name_server_record_data:?}");
                return DnsQuestionResolutionResult::Answer(name_server_record_data.clone());
            }
        }
        // Next, try to resolve any NS by reaching out
        for nameserver in nameservers.iter() {
            info!("\t\tRecursively resolving NS {nameserver}...");
            if let DnsQuestionResolutionResult::Answer(name_server_record_data) =
                self.resolve_question(&DnsRecord::new_question_a(&nameserver.0))
            {
                return DnsQuestionResolutionResult::Answer(name_server_record_data.clone());
            }
        }
        // Failed to resolve any nameserver
        // Technically this is either "can't reach" or "can't identify", but either is fine
        return DnsQuestionResolutionResult::CannotReachIntermediaryServer;
    }
}

/// Useful for testing
pub(crate) fn resolve_one_record(
    resolver: &DnsResolver,
    fqdn: &str,
    record_type: DnsRecordType,
) -> (DnsRecord, DnsQuestionResolutionResult) {
    let question = DnsRecord::new_question(fqdn, record_type, DnsRecordClass::Internet);
    let data = resolver.resolve_question(&question);
    info!("Resolved \"{fqdn}\": {data:?}");
    (question, data)
}
