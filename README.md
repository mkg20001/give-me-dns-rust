# give-me-dns

You have IPv6, want to connect to some device and your router can't do mDNS or local domains?

Or, for whatever other reason, you want to be spared the pain of typing out an IPv6 address?

Then give-me-dns(.net) is just right for you!

Simply connect via a TCP client of your liking (like `nc give-me-dns.net 9999`) and you'll get a temporary DNS subdomain

# Development

Enter the development shell:
```bash
nix develop
```

Start the server with auto-reload:
```bash
cargo watch -- cargo run config.yaml
```

Or run once:
```bash
cargo run -- config.yaml
```

Get a name:
```bash
nc localhost 9999
```

Query the DNS:
```bash
dig -p5354 @localhost example.6dns.me AAAA
```

Test the HTTP API:
```bash
curl -X POST http://localhost:8053/json
```
