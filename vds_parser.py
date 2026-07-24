import argparse
import lxml.etree as ET
import msgpack
import os.path
import sys
from pathlib import Path

from base64 import b32decode
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from datetime import datetime
from loguru import logger
from tddoc.c40 import c40

# pdf2image and pyzbar are optional dependencies for PDF QR reading
try:
    from pdf2image import convert_from_path
    from pyzbar.pyzbar import decode as zbar_decode
except ImportError:
    convert_from_path = None
    zbar_decode = None

def parse_header(header):
    magic = header[0:1].hex().upper()
    version = int.from_bytes(header[1:2], byteorder="big")
    ca_cert = c40.parse(header[2:8])
    ca_id = ca_cert[:4]
    cert_id = ca_cert[4:8]
    manifest = header[8:11].hex().upper()
    emission = datetime.fromtimestamp(int.from_bytes(header[11:15], byteorder="big"))

    print("Header:")
    print(f"\tMagic: {magic}")
    print(f"\tVersion: {version}")
    print(f"\tCA ID: {ca_id}")
    print(f"\tCertificate ID: {cert_id}")
    print(f"\tEmission date: {emission}")
    print(f"\tManifest: {manifest}")
    return manifest, ca_id, cert_id

def get_field_names(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    namespaces = {k if k is not None else 'default': v for k, v in root.nsmap.items()}
    return [f.get('name') for f in tree.xpath('//default:Payload/default:Fields/*', namespaces=namespaces)]

def parse_msg(data, field_names):
    print(f"Message:")

    unpacker = msgpack.Unpacker()
    unpacker.feed(data)

    for name in field_names:
        field = next(unpacker)
        if type(field) is list:
            field = f"{field[0]}{field[1]}" 
        print(f"\t{name}: {field}")
    print()

def parse_raw_msg(data):
    print(f"Message:")

    unpacker = msgpack.Unpacker()
    unpacker.feed(data)

    while True:
        try:
            field = next(unpacker)
        except StopIteration:
            break
        print(f"\tField: {field}")
    print()

def verify_signature(msg, header, signature, cert):
    public_key_bytes = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    key = ECC.import_key(public_key_bytes)
    h = SHA256.new(msg).digest()
    h = SHA256.new(header + h)
    verifier = DSS.new(key, 'deterministic-rfc6979')
    try:
        verifier.verify(h, signature)
        logger.success("The code is authentic")
    except ValueError:
        logger.error("The code is not authentic.")

if __name__ == "__main__":
    logger.remove()
    logger.add(sys.stderr, format="<level>{level: <8}</level>: <level>{message}</level>")

    parser = argparse.ArgumentParser()
    parser.add_argument('source', help='Base32 string or filename (txt or pdf)')
    parser.add_argument('--check-root', action="store_true", help='Check certificate signature with root certificate', default=False)
    args = parser.parse_args()

    source = args.source
    p = Path(source).expanduser()

    if p.suffix.lower() == '.txt':
        with open(p, "rb") as fd:
            source = fd.read().strip(b"\n")
    elif p.suffix.lower() == '.pdf':
        if convert_from_path is None or zbar_decode is None:
            raise ImportError("pdf2image and pyzbar are required for PDF QR reading")

        pages = convert_from_path(str(p), dpi=300)
        decoded_text = None
        for page in pages:
            qr_codes = zbar_decode(page)
            if qr_codes:
                decoded_text = qr_codes[0].data.decode('utf-8')
                break

        if not decoded_text:
            logger.error("No QR code found in PDF")
            sys.exit(1)

        source = decoded_text

    try:
        data = b32decode(source)
    except Exception as e:
        logger.error(f"Base32 decode error: {e}")
        sys.exit(1)

    if len(data) < 17:
        logger.error(f"Data too short ({len(data)} bytes, expected >=17).")
        sys.exit(1)

    header = data[:17]
    length = int.from_bytes(data[15:17], byteorder='big')

    if 17 + length > len(data):
        logger.error(f"Declared payload length {length} exceeds available bytes {len(data)-17}.")
        sys.exit(1)

    msg = data[17:17+length]
    sig = data[17+length:]
    manifest, ca_id, cert_id = parse_header(header)
    manifest_file = f"manifests/{manifest}.xml"
    
    if os.path.isfile(manifest_file):
        field_names = get_field_names(manifest_file)
        parse_msg(msg, field_names)
    else:
        logger.warning(f"Manifest {manifest_file} not found.")
        parse_raw_msg(msg)

    if args.check_root:
        # Root certificate
        with open(f"certificates/{ca_id}.crt", "rb") as fd:
            root_cert = x509.load_der_x509_certificate(fd.read())

    if not os.path.isfile(f"certificates/{ca_id+cert_id}.crt"):
        logger.error(f"Certificate {ca_id+cert_id}.crt not found, signature cannot be checked.")
        sys.exit(1)
    
    # Verify leaf certificate
    with open(f"certificates/{ca_id+cert_id}.crt", "rb") as fd:
        cert = x509.load_pem_x509_certificate(fd.read())
    
    if args.check_root:
        now = datetime.now(root_cert.not_valid_before_utc.tzinfo)
        if now < root_cert.not_valid_before_utc:
            logger.error(f"Root CA certificate is not yet valid (valid from {root_cert.not_valid_before_utc})")
            sys.exit(1)
        if now > root_cert.not_valid_after_utc:
            logger.error(f"Root CA certificate has expired (expired on {root_cert.not_valid_after_utc})")
            sys.exit(1)

        cert.verify_directly_issued_by(root_cert)
        logger.success("The certificate signature is valid")

    now = datetime.now(cert.not_valid_before_utc.tzinfo)
    if now < cert.not_valid_before_utc:
        logger.error(f"Certificate is not yet valid (valid from {cert.not_valid_before_utc})")
        sys.exit(1)
    if now > cert.not_valid_after_utc:
        logger.error(f"Certificate has expired (expired on {cert.not_valid_after_utc})")
        sys.exit(1)
    
    verify_signature(msg, header, sig, cert)