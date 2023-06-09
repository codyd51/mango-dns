<div align="center">
  <img src="logo.png" width="200">
  <h1>mango-dns</h1>
</div>

`mango-dns` is a recursive DNS resolver.

mango supports the common DNS record types:

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

mango does most of the usual fun stuff expected of a recursive DNS resolver:

* Functionality is valid: the high-level stack (i.e. web browsing, etc.) works
* Recursively resolve queries, starting from the root DNS servers
* Parse and generate DNS packets
* Cache records and respond from the cache (both when responding to queries and when recursing)
* Send `NXDOMAIN`/`SOA` records in response to unreachable queries

## License
MIT license. 