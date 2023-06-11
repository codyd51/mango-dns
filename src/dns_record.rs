use std::fmt::{Display, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum DnsPacketRecordType {
    QuestionRecord,
    AnswerRecord,
    AuthorityRecord,
    AdditionalRecord,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub(crate) enum DnsRecordType {
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
    Text = 16,
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
            16 => Ok(Self::Text),
            _ => Err(value),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub(crate) enum DnsRecordClass {
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
pub(crate) struct DnsRecordTtl(pub(crate) usize);
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub(crate) struct FullyQualifiedDomainName(pub(crate) String);

impl Display for FullyQualifiedDomainName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "FQDN({})", self.0)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct StartOfAuthorityRecordData {
    primary_name_server: FullyQualifiedDomainName,
    responsible_mailbox: FullyQualifiedDomainName,
    serial_number: usize,
    refresh_interval: usize,
    retry_interval: usize,
    expire_limit: usize,
    minimum_ttl: usize,
}

impl StartOfAuthorityRecordData {
    pub(crate) fn new(
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

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct EDNSOptRecordData {
    udp_payload_size: usize,
    extended_opcode: usize,
    version: usize,
    flags: usize,
    options_data: Vec<u8>,
}

impl EDNSOptRecordData {
    pub(crate) fn new(
        udp_payload_size: usize,
        extended_opcode: usize,
        version: usize,
        flags: usize,
        options_data: &[u8],
    ) -> Self {
        Self {
            udp_payload_size,
            extended_opcode,
            version,
            flags,
            options_data: options_data.to_vec(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct HttpsRecordData {
    svc_priority: usize,
    target_name: String,
    svc_param_key: usize,
    supported_protocols: Vec<String>,
}

impl HttpsRecordData {
    pub(crate) fn new(
        svc_priority: usize,
        target_name: String,
        svc_param_key: usize,
        supported_protocols: Vec<String>,
    ) -> Self {
        Self {
            svc_priority,
            target_name,
            svc_param_key,
            supported_protocols,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum DnsRecordData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    NameServer(FullyQualifiedDomainName),
    CanonicalName(FullyQualifiedDomainName),
    StartOfAuthority(StartOfAuthorityRecordData),
    EDNSOpt(EDNSOptRecordData),
    Pointer(FullyQualifiedDomainName),
    Https(HttpsRecordData),
}

impl From<&DnsRecordData> for DnsRecordType {
    fn from(value: &DnsRecordData) -> Self {
        match value {
            DnsRecordData::A(_) => DnsRecordType::A,
            DnsRecordData::AAAA(_) => DnsRecordType::AAAA,
            DnsRecordData::NameServer(_) => DnsRecordType::NameServer,
            DnsRecordData::CanonicalName(_) => DnsRecordType::CanonicalName,
            DnsRecordData::StartOfAuthority(_) => DnsRecordType::StartOfAuthority,
            DnsRecordData::EDNSOpt(_) => DnsRecordType::EDNSOpt,
            DnsRecordData::Pointer(_) => DnsRecordType::Pointer,
            DnsRecordData::Https(_) => DnsRecordType::Https,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DnsRecord {
    pub(crate) name: String,
    pub(crate) record_type: DnsRecordType,
    // This field isn't valid for EDNS records
    pub(crate) record_class: Option<DnsRecordClass>,
    // The below fields aren't valid for Question records
    pub(crate) record_ttl: Option<DnsRecordTtl>,
    pub(crate) record_data: Option<DnsRecordData>,
}

impl DnsRecord {
    pub(crate) fn new(
        name: &str,
        record_type: DnsRecordType,
        record_class: Option<DnsRecordClass>,
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

    pub(crate) fn new_question(
        name: &str,
        record_type: DnsRecordType,
        record_class: DnsRecordClass,
    ) -> Self {
        Self {
            name: name.to_string(),
            record_type,
            record_class: Some(record_class),
            record_ttl: None,
            record_data: None,
        }
    }

    pub(crate) fn new_question_a(name: &str) -> Self {
        Self::new_question(name, DnsRecordType::A, DnsRecordClass::Internet)
    }
}

impl Display for DnsRecord {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let record_type = match self.record_type {
            DnsRecordType::A => "A",
            DnsRecordType::AAAA => "AAAA",
            DnsRecordType::Pointer => "PTR",
            DnsRecordType::SVCB => "SVCB",
            DnsRecordType::StartOfAuthority => "SOA",
            DnsRecordType::Https => "HTTPS",
            DnsRecordType::NameServer => "NS",
            DnsRecordType::CanonicalName => "CNAME",
            DnsRecordType::DelegationSigner => "DS",
            DnsRecordType::EDNSOpt => "OPT",
            DnsRecordType::Text => "TXT",
        };
        let maybe_record_data_as_string = match &self.record_data {
            None => None,
            Some(record_data) => match record_data {
                DnsRecordData::A(ipv4_addr) => Some(format!("{ipv4_addr}")),
                DnsRecordData::AAAA(ipv6_addr) => Some(format!("{ipv6_addr}")),
                DnsRecordData::NameServer(fqdn) => Some(format!("{fqdn}")),
                DnsRecordData::CanonicalName(fqdn) => Some(format!("{fqdn}")),
                DnsRecordData::StartOfAuthority(soa) => Some(format!("{soa:?}")),
                DnsRecordData::EDNSOpt(edns_opt) => Some(format!("{edns_opt:?}")),
                DnsRecordData::Pointer(fqdn) => Some(format!("{fqdn}")),
                DnsRecordData::Https(https) => Some(format!("{https:?}")),
            },
        };
        let name = &self.name;
        match maybe_record_data_as_string {
            None => write!(f, "DnsRecord[{name}, {record_type}]"),
            Some(record_data_as_string) => write!(
                f,
                "DnsRecord[{name}, {record_type}, {record_data_as_string}]"
            ),
        }
    }
}
