<div align="center">
  <img src="spread.png">
</div>

mango-dns is a recursive DNS resolver. The major areas of functionality include:

* Event loop
* Packet parsing
* Recursive resolution
* Packet generation

mango uses [tokio](https://github.com/tokio-rs/tokio) to help manage its event loop and distribute DNS queries. DNS parsing, resolution, and packet resolution, is implemented in-house. 

mango does most of the usual fun stuff expected of a recursive DNS resolver:

* Functionality is valid: the high-level stack (i.e. web browsing, etc.) works
* Recursively resolve queries, starting from the root DNS servers
* Parse and generate DNS packets and many record types
* Cache records and respond from the cache (both when responding to queries and when recursing)
* Send `NXDOMAIN`/`SOA` records in response to unreachable queries

### Packet parsing

I use mango as my DNS resolver, so all the traffic that I see on my home network is covered by mango. This includes extensions to DNS, such as [DNS-SD](http://www.dns-sd.org), [EDNS](https://en.wikipedia.org/wiki/Extension_Mechanisms_for_DNS), and [SVCB/HTTPS](https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/11/?include_text=1) records.

mango supports parsing a variety of record types:

```text
A
AAAA
NS
CNAME
PTR
SVCB
SOA
HTTPS
DS
OPT
```

... and more if you call now!

Like any good Rust crate, mango reflects the structure of the domain in the type system. For example, mango uses sum types to carry the data associated with each DNS record:

```rust
pub(crate) enum DnsRecordData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    NameServer(FullyQualifiedDomainName),
    CanonicalName(FullyQualifiedDomainName),
    StartOfAuthority(StartOfAuthorityRecordData),
    EDNSOpt(EDNSOptRecordData),
    Pointer(FullyQualifiedDomainName),
    Https(HttpsRecordData),
    DelegationSigner(DelegationSignerRecordData),
    // ...
}
```

DNS names are encoded using a compression scheme utilizing the fundamental components of labels and pointers. DNS names can be encoded as:
* A pointer to a previous name
* A sequence of labels ending in a pointer
* A sequence of labels ending in a zero byte

mango supports parsing names via `DnsPacketBodyParser.parse_name(&mut self) -> Option<String>`.

More generally, packets can be parsed from a raw buffer off a socket via `DnsPacketParser::parse_packet_buffer(buf: &[u8]) -> DnsPacket`.

### Packet generation

mango includes some nifty internal APIs. For example, to generate a DNS packet:

```rust
let output_packet = DnsPacketWriter::new()
    .params(
        DnsPacketWriterParams::new(
            transaction_id,
            DnsOpcode::Query,
            PacketDirection::Response(ResponseFields::new(
                DnsPacketResponseCode::Success,
            )),
        )
    )
    .questions(&[&original_answer]),
    .answers(&[
        DnsRecord::new_answer(
            "www.axleos.com",
            DnsRecordType::A,
            DnsRecordTtl(300),
        )
    ])
    .write();
);
```

These APIs output correct packets, including with trickier record encodings such as `HTTPS`. 

### Resolution

The resolver can be asked to answer a query:

```rust
enum DnsQuestionResolutionResult {
    Answer(DnsRecordData),
    NoDomain,
    CannotResolveRecordType,
    CannotReachIntermediaryServer,
    CannotIdentifyIntermediaryServer,
}

impl DnsResolver {
    fn resolve_question(
        &self, 
        question: &DnsRecord
    ) -> DnsQuestionResolutionResult {}
}
```

An explicit lookup to another DNS server can be performed:

```rust
impl DnsResolver {
    fn send_question_and_await_response(
        &self,
        dest: &SocketAddr,
        question: &DnsRecord,
    ) -> Option<DnsPacket> {}
}
```

An explicit cache lookup can be performed:

```rust
enum CacheLookupPolicy {
    /// Virgin Media doesn't support IPv6, so don't try to follow IPv6 records during internal resolution
    SuitableForRecursiveResolution,
    /// Returns the answer for the query regardless of whether we can actually connect to the resource
    SuitableForAnsweringQuery,
}

impl DnsResolver {
    fn get_record_from_cache(
        &self,
        fqdn: &FullyQualifiedDomainName,
        lookup_policy: CacheLookupPolicy
    ) -> Option<DnsRecordData> {}
}
```

Given a set of nameservers from an intermediary query, one can be selected for continuing resolution:

```rust
impl DnsResolver {
    fn select_and_resolve_nameserver_from_pool(
        &self,
        nameservers: Vec<FullyQualifiedDomainName>,
    ) -> DnsQuestionResolutionResult {}
}
```

## License
MIT license. 