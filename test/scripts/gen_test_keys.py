#!/usr/bin/env python3

import os
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta

# ---- Configuration ----
TESTDIR = Path(__file__).resolve().parent.parent
PRIVATE = TESTDIR / "private"
SERVER = TESTDIR / "server"

CA_KEY = PRIVATE / "rootCA.key"
CA_CERT = PRIVATE / "rootCA.pem"
SIGNER_KEY = PRIVATE / "private.key"
SIGNER_CERT = SERVER / "manifest.crt"

CA_SUBJECT = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"OTA Test Root CA")])
SIGNER_SUBJECT = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"OTA Manifest Signer")])

def ensure_dirs():
    PRIVATE.mkdir(parents=True, exist_ok=True)
    SERVER.mkdir(parents=True, exist_ok=True)

def gen_root_ca():
    print(f"[*] Generating Root CA key ({CA_KEY}) and cert ({CA_CERT})...")
    ca_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(CA_SUBJECT)
        .issuer_name(CA_SUBJECT)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=1), critical=True
        )
        .sign(ca_key, hashes.SHA256(), default_backend())
    )
    # Save
    with open(CA_KEY, "wb") as f:
        f.write(ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))
    with open(CA_CERT, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    print("    Done.")

def gen_signer_cert():
    print(f"[*] Generating signer key ({SIGNER_KEY}) and manifest cert ({SIGNER_CERT}) signed by Root CA...")
    # Load CA
    with open(CA_KEY, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    with open(CA_CERT, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), backend=default_backend())

    signer_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    signer_csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(SIGNER_SUBJECT)
        .sign(signer_key, hashes.SHA256(), default_backend())
    )

    # CA signs CSR to create signer cert
    signer_cert = (
        x509.CertificateBuilder()
        .subject_name(signer_csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(signer_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=730))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .sign(ca_key, hashes.SHA256(), default_backend())
    )

    with open(SIGNER_KEY, "wb") as f:
        f.write(signer_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))
    with open(SIGNER_CERT, "wb") as f:
        f.write(signer_cert.public_bytes(serialization.Encoding.PEM))
    print("    Done.")

def main():
    ensure_dirs()
    gen_root_ca()
    gen_signer_cert()
    print("\nTest CA, signer, and manifest cert generated.\n")
    print(f"  Root CA key:     {CA_KEY}")
    print(f"  Root CA cert:    {CA_CERT}")
    print(f"  Signer key:      {SIGNER_KEY}")
    print(f"  Manifest cert:   {SIGNER_CERT}")

if __name__ == "__main__":
    main()

