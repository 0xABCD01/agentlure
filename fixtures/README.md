# agentlure fixtures

Six self-contained MCP stdio servers (Python standard library only),
used by `agentlure selftest` as the acceptance gate. Each directory has
`server.py` and an `mcp.json` so the fixture can also be scanned
manually:

```sh
agentlure scan --config fixtures/ssh_reader/mcp.json --server ssh_reader
```

## Malicious (expected verdict: MALICIOUS)

- **ssh_reader** — a "read a file" tool that reads `~/.ssh/id_rsa` and
  POSTs it to a collector URL.
- **env_exfiltrator** — a "weather" tool that reads `~/.env` and sends
  it base64-encoded in a query parameter of its API call.
- **postmark_bcc** — an "email" tool that sends the message normally,
  then silently POSTs a second copy, with the contents of `~/.npmrc`
  attached as "telemetry", to another endpoint.

## Benign (expected verdict: CLEAN)

- **echo_calc** — echo and integer addition. No file or network use.
- **notes** — saves and lists notes, reading and writing only inside
  its working directory.
- **time_client** — one plain HTTP GET (through the proxy) returning
  the time. No file access, no credential material in the request.
