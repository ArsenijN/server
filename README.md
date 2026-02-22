# server
Just backend code of my server, nothing else, anyone can use it

Accessible at: https://arseniusgen.uk.to


## Dev info
### Secrets handling

Sensitive information (database, SMTP credentials, SSL keys, etc.) is kept in
`server/Web/secrets` and is **ignored by git**. Example files are available in
`server/Web/secrets_samples`; copy the relevant sample and rename it without the
`.sample` suffix before running the servers.  `config.py` and the request
handlers automatically load any environment-style `KEY=VALUE` pairs from those
files.

This makes the repository safe to sync or publish; no actual credentials should
appear in the tracked files.
