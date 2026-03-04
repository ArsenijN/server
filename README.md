# server
Just backend code of my server, nothing else, anyone can use it

Currently, server is **NOT production-ready!!!** (see: [FluxDrop Audit](./fluxdrop_audit.md))

Accessible at: https://arseniusgen.uk.to

FluxDrop accessible at: https://arseniusgen.uk.to/fluxdrop_pp/

## FluxDrop relations to this server

This server is a part of my own projects, like FluxDrop (whole CDN 
implementation) and [driveguard](https://github.com/ArsenijN/driveguard) (OTA 
updates, etc.). Since I make my own file hosting thing, I want to make it's 
design "very human". So... there we are

FluxDrop and entire server now operates with proper HTTPS thanks to **Let's 
Encrypt**'s certificates! Test it out at: arseniusgen.uk.to or 
arsenius-gen.uk.to

Q: Why you doesn't used Let's Encrypt before?
A: High usage of domain. Yes, since I technically own a subdomain and not a 
domain, provided by [FreeDNS](https://freedns.afraid.org/subdomain/), I was 
restricted by the thing that other users also uses the subdomains from uk.to, 
and... In 2023 I was not able to do this since Let's Encrypt said that "there's 
a lot of certs already made for this domain", and... Self-signed certs is only 
thing that was made all of this happened. At 2026 usage was lowered (or the 
thing that uk.to now a shealth domain, basically no one can now use it except 
those who used it before?) and I was able to do the certificates successfully 
right and... Now there we are

## Dev info
### Secrets handling

Sensitive information (database, SMTP credentials, SSL keys, etc.) is kept in 
`server/Web/secrets` and is **ignored by git**. Example files are available in 
`server/Web/secrets_samples`; copy the relevant sample and rename it without 
the `.sample` suffix before running the servers.  `config.py` and the request 
handlers automatically load any environment-style `KEY=VALUE` pairs from those 
files.

This makes the repository safe to sync or publish; no actual credentials should 
appear in the tracked files.
