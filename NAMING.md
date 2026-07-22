# Naming

## Public identity

The public product name is **NoTUG**, expanded as **No Touching Unless Granted**.

Current technical identifiers preserve their normal separator conventions:

- Python distribution: `notug-protocol`
- Python import package: `notug_protocol`
- console command: `notug`
- policy example: `examples/notug.toml`
- environment variables: `NOTUG_*`
- generated Git namespace: `notug/` and `refs/notug/`
- default vault directory: `notug-protocol`

Runtime public-identity constants are centralized in `src/notug_protocol/brand.py`.

## Intentionally retained v1 compatibility identifiers

The rename does not silently rewrite cryptographic or canonical v1 protocol identifiers. Existing v1
hash domains remain byte-for-byte `NoTUG.*.v1`, the Tug schema retains the field `notug_version`, and the
policy schema retains the key `notug_metadata`. These are compatibility identifiers, not the public
product name.

Changing any of those values would alter hashes or canonical schema interpretation and requires an
explicit protocol-version change plus migration and verification rules. They must not be replaced by a
blind repository-wide rename.

## Review required before public distribution

Before publishing a repository or package, a human must perform:

- trademark and confusing-similarity review in intended jurisdictions;
- Python package index and command-name availability review;
- source-hosting organization and repository-name review;
- domain and social-name review only if those channels are actually planned;
- cultural, accessibility, searchability, and professional-audience review;
- review of generated branch prefixes, vault directory names, environment variables, and documentation.

Record the result in [DECISIONS.md](DECISIONS.md). Do not publish merely because a local build succeeds.
