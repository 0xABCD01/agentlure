# agentlure

Detonate MCP servers against fake credentials before you install them.

agentlure runs an untrusted MCP server inside a sandbox planted with
canary credentials, fake contacts, and a sinkholed network, then reports
what the server actually tried to read or send out. A deterministic
verdict, built for CI: no account, no LLM judge, no static pattern
guesses.

**Status: in planning. No release yet.**
