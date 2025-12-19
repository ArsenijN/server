This directory holds sensitive artifacts that MUST NOT be committed to source control.

- Place real SSL certificates in `myCA.pem` and `myCA.key`.
- Place the SQLite DB as `fluxdrop_users.db`.
- Place a blacklist file as `blklst.txt`.
- Place audit logs as `audit.log`.

When deploying, ensure this directory is owned by the service user and is not world-readable.
