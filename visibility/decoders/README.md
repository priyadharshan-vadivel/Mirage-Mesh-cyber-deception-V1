# Decoders — why there is no custom decoder

Mirage Mesh deliberately ships **no custom Wazuh decoder**, and that is the
correct design, not an omission.

Each decoy writes structured JSON (one object per line) into its log file. The
Wazuh agent reads those files with `log_format=json` (see
`../agent/ossec-localfile.conf`), so Wazuh's built-in JSON decoder parses every
event automatically and exposes the fields to rules in dot notation —
`mirage_mesh.decoy_layer`, `mirage_mesh.source_ip`, `mirage_mesh.severity`, and
so on.

Adding a hand-written decoder on top of already-structured JSON would only
create a chance to *conflict* with the built-in decoding. Keeping the contract
as "emit clean JSON, let Wazuh decode it" is exactly what makes the shared schema
the single interface boundary: the rules in `../rules/mirage_mesh_rules.xml`
match those decoded fields directly.

If a future decoy ever needs to emit plain (non-JSON) text, add a decoder here
then — but the four PoC decoys do not.
