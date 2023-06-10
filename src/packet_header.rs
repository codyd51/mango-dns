use crate::packet_header_layout::{DnsOpcode, DnsPacketHeaderRaw, DnsPacketResponseCode};
use std::fmt::{Display, Formatter};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) struct ResponseFields {
    is_authority: bool,
    is_recursion_available: bool,
    pub(crate) response_code: DnsPacketResponseCode,
}

impl ResponseFields {
    pub(crate) fn new(
        is_authority: bool,
        is_recursion_available: bool,
        response_code: DnsPacketResponseCode,
    ) -> Self {
        Self {
            is_authority,
            is_recursion_available,
            response_code,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum PacketDirection {
    Query,
    Response(ResponseFields),
}

#[derive(Debug, Clone)]
pub(crate) struct DnsPacketHeader {
    pub(crate) identifier: usize,
    pub(crate) direction: PacketDirection,
    pub(crate) opcode: DnsOpcode,
    pub(crate) response_code: DnsPacketResponseCode,
    pub(crate) is_truncated: bool,
    pub(crate) is_recursion_desired: bool,
    pub(crate) is_recursion_available: bool,
    pub(crate) question_count: usize,
    pub(crate) answer_count: usize,
    pub(crate) authority_count: usize,
    pub(crate) additional_record_count: usize,
}

impl From<&DnsPacketHeaderRaw> for DnsPacketHeader {
    fn from(raw: &DnsPacketHeaderRaw) -> Self {
        Self {
            identifier: raw.identifier(),
            direction: match raw.is_response() {
                true => PacketDirection::Response(ResponseFields::new(
                    raw.is_authoritative_answer(),
                    raw.is_recursion_available(),
                    raw.response_code().try_into().unwrap(),
                )),
                false => PacketDirection::Query,
            },
            opcode: DnsOpcode::try_from(raw.opcode())
                .unwrap_or_else(|op| panic!("Unexpected DNS opcode: {}", op)),
            response_code: DnsPacketResponseCode::try_from(raw.response_code())
                .unwrap_or_else(|val| panic!("Unexpected response code: {}", val)),
            is_truncated: raw.is_truncated(),
            is_recursion_desired: raw.is_recursion_desired(),
            is_recursion_available: raw.is_recursion_available(),
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
                writeln!(
                    f,
                    "{}",
                    match response_fields.is_authority {
                        true => "\t[Authoritative]",
                        false => "\t[Non-authoritative]",
                    }
                )?;

                writeln!(
                    f,
                    "{}",
                    match response_fields.is_recursion_available {
                        true => "\t[Recursive]",
                        false => "\t[Non-recursive]",
                    }
                )?;

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
