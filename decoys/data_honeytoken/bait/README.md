# Bait templates (honeytokens)

`aws_credentials.template` is rendered by `setup.sh` to the bait path on the VM
(default `/opt/backup/.aws/credentials`). It is **not a real credential**:

- The values are deliberately invalid example keys carrying `MIRAGE` / `EXAMPLE`
  markers, so if the file ever leaks it is instantly identifiable as a decoy and
  grants access to nothing (RISKS.md, R3).
- The file has no developer "this is a honeytoken" banner *inside it* on purpose
  — that would tip off an attacker who `cat`s it. The tell lives here in the
  repo, not in the deployed bait.
- Only `*.template` files are committed. The **rendered** file is created on the
  VM at setup time and is never committed (see the repo `.gitignore`).

Any process that reads the rendered file trips the auditd rule tagged
`mirage_honeytoken`, which `honeytoken_watch.py` turns into a decoy alert.
