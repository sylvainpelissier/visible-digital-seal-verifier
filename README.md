# Visible Digital Seal verifier

This script decodes Visible Digital Seals (VDS) and verify their authenticity.

Tested on the "Cachet Electronique Visible" (CEV) from France Identité document attestation.

## Requirements

- Python 3.10+
- `poetry install` (recommended, `pyproject.toml` is provided)- Or for pip users:
  - `pip install lxml msgpack pycryptodome cryptography tdd`
- Optional for PDF QR reading:
  - `pip install pdf2image pyzbar pillow`
  - System packages: `poppler-utils` (for `pdf2image`) and `zbar` (for `pyzbar`)

## Usage

Base32 string:

```bash
python QR/2ddoc_attestation/2ddoc.py 3YBHXHJ3J6U...
```

Text file containing Base32 code:

```bash
python QR/2ddoc_attestation/2ddoc.py code.txt
```

PDF containing QR code:

```bash
python QR/2ddoc_attestation/2ddoc.py /path/to/qrcode.pdf
```

## Notes

The manifests on the certificates should be extracted first from the application from example:

```bash
$ unzip -j fr.gouv.franceidentite.apk "assets/manifests/*.xml" -d manifests
$ unzip -j fr.gouv.franceidentite.apk "assets/certificates/*.crt" -d certificates
```

# Limitations

* QR code or base32 decoding
* No check on revocation dates
* Support only ECDSA with P-256 curve verification