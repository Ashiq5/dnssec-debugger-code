import base64
import re

import dns.dnssec
import dns.name
import dns.rdatatype
import dns.rrset
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from utils.logging_utils import logger


def load_private_key_from_pem(filepath: str):
    with open(filepath, "rb") as pem_file:
        pem_data = pem_file.read()

    # Deserialize the private key based on its type (ECDSA or RSA)
    try:
        private_key = serialization.load_pem_private_key(
            pem_data,
            password=None,  # If the key is encrypted, provide the password here
        )
        return private_key
    except ValueError as e:
        logger.logger.error("Failed to load private key:", e)


def load_private_key_from_bind(file_path: str):
    """
    Load an RSA private key from a BIND-style .private file.

    Example contents of a .private file for an RSA key:
        Private-key-format: v1.3
        Algorithm: 8 (RSASHA256)
        Modulus: xxxxxxxxxxxxxx (base64)
        PublicExponent: xxxxxxx (base64)
        PrivateExponent: xxxxxxx (base64)
        Prime1: xxxxxxx (base64)
        Prime2: xxxxxxx (base64)
        Exponent1: xxxxxxx (base64)
        Exponent2: xxxxxxx (base64)
        Coefficient: xxxxxxx (base64)
    """
    # Dictionary to store the parsed fields
    fields = {}

    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or ":" not in line:
                continue
            key, val = line.split(":", 1)
            key = key.strip()
            val = val.strip()
            # Some lines might have comments in parentheses: "Algorithm: 8 (RSASHA256)"
            # We'll remove parentheses to get just the number or base64 data
            val = re.sub(r"\(.*?\)", "", val).strip()
            fields[key] = val

    # Check that this is indeed an RSA key (Algorithm: 8 or 7 or 5, etc. for RSA variants)
    # For RSASHA256, "Algorithm: 8" is common
    algorithm = fields.get("Algorithm")
    if not algorithm or not algorithm.startswith(("7", "8", "5", "10")):
        # 5=RSASHA1, 7=RSASHA1-NSEC3, 8=RSASHA256, 10=RSASHA512, etc.
        if algorithm.startswith("13"):
            return load_ecdsa_p256_private_key_from_bind_file(file_path)
        raise ValueError(
            "This example only handles RSA keys (Algorithm 5/7/8/10...). Found: "
            + str(algorithm)
        )

    # Extract base64-encoded parameters
    # The line might look like 'Modulus: w93X4f...base64string...'
    # We decode each from base64 into bytes, then convert to int
    def b64_to_int(b64_string: str) -> int:
        return int.from_bytes(base64.b64decode(b64_string), byteorder="big")

    modulus = b64_to_int(fields["Modulus"])
    public_exponent = b64_to_int(fields["PublicExponent"])
    private_exponent = b64_to_int(fields["PrivateExponent"])
    prime1 = b64_to_int(fields["Prime1"])
    prime2 = b64_to_int(fields["Prime2"])
    exponent1 = b64_to_int(fields["Exponent1"])  # d mod (p-1)
    exponent2 = b64_to_int(fields["Exponent2"])  # d mod (q-1)
    coefficient = b64_to_int(fields["Coefficient"])  # q^(-1) mod p

    # Reconstruct RSA private key parameters
    rsa_numbers = rsa.RSAPrivateNumbers(
        p=prime1,
        q=prime2,
        d=private_exponent,
        dmp1=exponent1,
        dmq1=exponent2,
        iqmp=coefficient,
        public_numbers=rsa.RSAPublicNumbers(e=public_exponent, n=modulus),
    )

    private_key = rsa_numbers.private_key()
    return private_key

def load_ecdsa_p384_private_key_from_bind_file(filename):
    """
    Loads an ECDSA P-256 (algorithm 13) private key from a BIND .private file.
    Returns a cryptography 'EllipticCurvePrivateKey' object.
    """
    """
        Loads an ECDSA P-384 (algorithm 14) private key from a BIND .private file.
        Returns a cryptography 'EllipticCurvePrivateKey' object.
        """
    private_key_b64 = None

    # Read the .private file line by line
    with open(filename, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("PrivateKey:"):
                _, b64_val = line.split(":", 1)
                private_key_b64 = b64_val.strip()
                break

    if not private_key_b64:
        raise ValueError("No 'PrivateKey' field found in the BIND file.")

    # Decode the base64-encoded private key (raw scalar)
    raw_scalar = base64.b64decode(private_key_b64)

    if len(raw_scalar) != 48:
        raise ValueError(f"Unexpected scalar length for P-384: {len(raw_scalar)} bytes")

    # Convert bytes to int, then derive the EC private key
    scalar_int = int.from_bytes(raw_scalar, byteorder="big")
    private_key = ec.derive_private_key(scalar_int, ec.SECP384R1())

    return private_key


def load_ecdsa_p256_private_key_from_bind_file(filename):
    """
    Loads an ECDSA P-256 (algorithm 13) private key from a BIND .private file.
    Returns a cryptography 'EllipticCurvePrivateKey' object.
    """
    private_key_b64 = None

    # Read the .private file line by line
    with open(filename, "r") as f:
        for line in f:
            line = line.strip()
            # Example line: "PrivateKey: gZ5nSyJIRIO29MdvGh0mR2C2S9wSyoSuFl5xLM4qT9w="
            if line.startswith("PrivateKey:"):
                _, b64_val = line.split(":", 1)
                private_key_b64 = b64_val.strip()
                break

    if not private_key_b64:
        raise ValueError("No 'PrivateKey' field found in the BIND file.")

    # Decode the base64-encoded private key (raw scalar)
    raw_scalar = base64.b64decode(private_key_b64)

    # BIND ECDSA keys for P-256 are just the raw 32-byte scalar
    # Convert bytes to int, then derive the EC private key
    scalar_int = int.from_bytes(raw_scalar, byteorder="big")
    private_key = ec.derive_private_key(scalar_int, ec.SECP256R1())

    return private_key


def load_public_key_from_base64(b64_key: str):
    """
    Decodes a Base64-encoded string and
    return the bytes format
    """
    # 1. Decode the Base64 string into raw bytes
    key_bytes = base64.b64decode(b64_key)
    return key_bytes


def generate_ecdsa_zsk():
    """Generate an ECDSA-based Zone Signing Key (ZSK)"""
    key = ec.generate_private_key(ec.SECP256R1())  # P-256 curve

    private_key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    public_key_base64 = base64.b64encode(public_key).decode("utf-8")

    return private_key_pem.decode(), public_key_base64


def generate_rsa_zsk():
    """Generate an RSA-based Zone Signing Key (ZSK)"""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Extract private and public key components
    private_key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Convert to base64 (to match DNSKEY record format)
    public_key_base64 = base64.b64encode(public_key).decode("utf-8")

    return private_key_pem.decode(), public_key_base64


def create_dnskey_record(
    zone_name, public_key_base64, algorithm=8, flags=256, protocol=3
):
    """Create a DNSKEY record for the ZSK."""
    # Flag = 256 for ZSK
    # Protocol = 3 for DNS

    dnskey = dns.rdtypes.ANY.DNSKEY.DNSKEY(
        dns.rdataclass.IN,
        dns.rdatatype.DNSKEY,
        flags,
        protocol,
        algorithm,
        base64.b64decode(public_key_base64),
    )

    rrset = dns.rrset.from_rdata_list(zone_name, 3600, [dnskey])  # 1-hour TTL
    return rrset


def generate_key():
    """Generate a DNSK KEY  for DNSSEC using ECDSA P-256."""
    # Generate the private key
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Extract public key in uncompressed format (X9.62)
    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )

    # Convert to Base64 (needed for DNSKEY)

    return private_key


def private_key_to_public_key_base64(private_key):
    public_key = private_key.public_key()

    # Serialize the public key in raw format (X and Y coordinates concatenated)
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,  # Uncompressed format
        format=serialization.PublicFormat.UncompressedPoint,
    )

    # Convert to Base64
    public_key_base64 = base64.b64encode(public_key_bytes).decode("utf-8")
    return public_key_base64

def base64_encode_int(value):
    """Encodes an integer to Base64 in big-endian format."""
    return base64.b64encode(
        value.to_bytes((value.bit_length() + 7) // 8, "big")
    ).decode("utf-8")