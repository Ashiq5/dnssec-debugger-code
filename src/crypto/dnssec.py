import base64
import hashlib
import os
import random
import re
import secrets
from datetime import datetime
from enum import IntEnum
from typing import List, Optional, Union

import dns
import dns.dnssec
import dns.name
import dns.rdatatype
import dns.rdatatype
import dns.rrset
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from dns.dnssec import NSEC3Hash
from dns.rdtypes.ANY.DNSKEY import DNSKEY

from utils.logging_utils import logger
from .utils import base64_encode_int

key_algo_list_usable = [7, 8, 10, 13, 14]

key_algo_list_not_usable = [
    0,
    1,
    2,
    3,
    5,
    4,
    6,
    11,
    12,
    15,
    16,
    18,
    19,
    21,
    200,
    252,
    253,
    254,
    255,
]


def get_random_algo_not_in_list(algo_list):
    diff = set(key_algo_list_usable) - set(algo_list)
    if len(diff) == 0:
        raise Exception(
            f"Not possible to have a different algorithm than in list {algo_list}"
        )

    return random.choice(list(diff))


class DigestAlgorithm(IntEnum):
    "As defined by IANA : https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml"

    SHA1 = 1  # Mandatory
    SHA256 = 2  # Mandatory
    GOSTR341194 = 3  # Deprecated
    SHA384 = 4  # Optional
    GOSTR34112021 = 5  # Optional
    SM3 = 6  # Optional


class KeyFlags(IntEnum):
    ZSK = 256
    KSK = 257


class KeyAlgorithm(IntEnum):
    """
    As defined by IANA : https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
    """

    DELETE = 0
    RSAMD5 = 1
    DH = 2
    DSA = 3
    RSASHA1 = 5
    DSANSEC3SHA1 = 6
    RSASHA1NSEC3SHA1 = 7
    RSASHA256 = 8
    RSASHA512 = 10
    ECCGOST = 12
    ECDSAP256SHA256 = 13
    ECDSAP384SHA384 = 14
    ED25519 = 15
    ED448 = 16
    SM2SM3 = 17
    ECCGOST12 = 18


keyalgo_to_algo_dict = {
    5: "RSASHA1",
    7: "NSEC3RSASHA1",
    8: "RSASHA256",
    10: "RSASHA512",
    13: "ECDSAP256SHA256",
    14: "ECDSAP384SHA384",
    15: "ED25519",
    16: "ED448",
}


def make_dnskey_rdata(
    zone_name: str,
    public_key_base64,
    algorithm: KeyAlgorithm,
    key_flags: KeyFlags,
    protocol=3,  # all KEY and DNSKEY records are required to have a  Protocol Octet value of 3.
    ttl=3600,  # 1-hour TTL
):
    return dns.rdtypes.ANY.DNSKEY.DNSKEY(
        dns.rdataclass.IN,
        dns.rdatatype.DNSKEY,
        key_flags,
        protocol,
        algorithm,
        base64.b64decode(public_key_base64),
    )


def load_ecdsa_p384_private_key_from_bind_file(str_content: str):
    """
    Loads an ECDSA P-384 (algorithm 14) private key from a BIND .private file.
    Returns a cryptography 'EllipticCurvePrivateKey' object.
    """
    private_key_b64 = None

    # Read the .private file line by line
    for line in str_content.split("\n"):
        line = line.strip()
        if line.startswith("PrivateKey:"):
            _, b64_val = line.split(":", 1)
            private_key_b64 = b64_val.strip()
            break

    if not private_key_b64:
        raise ValueError("No 'PrivateKey' field found in the BIND file.")

    # Decode the base64-encoded private key (raw scalar)
    raw_scalar = base64.b64decode(private_key_b64)

    # BIND ECDSA keys for P-384 are 48 bytes long
    if len(raw_scalar) != 48:
        raise ValueError(
            "Invalid private key length for ECDSA P-384. Expected 48 bytes."
        )

    # Convert bytes to int, then derive the EC private key
    scalar_int = int.from_bytes(raw_scalar, byteorder="big")
    private_key = ec.derive_private_key(scalar_int, ec.SECP384R1())

    return private_key


def load_ecdsa_p256_private_key_from_bind_file(str_content: str):
    """
    Loads an ECDSA P-256 (algorithm 13) private key from a BIND .private file.
    Returns a cryptography 'EllipticCurvePrivateKey' object.
    """
    private_key_b64 = None

    # Read the .private file line by line

    for line in str_content.split("\n"):
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


def load_ed25519_private_key_from_bind_file(str_content: str):
    """
    Loads an Ed25519 (algorithm 15) private key from a BIND .private file.
    Returns a cryptography 'Ed25519PrivateKey' object.
    """
    private_key_b64 = None

    # Read the .private file line by line
    for line in str_content.split("\n"):
        line = line.strip()
        if line.startswith("PrivateKey:"):
            _, b64_val = line.split(":", 1)
            private_key_b64 = b64_val.strip()
            break

    if not private_key_b64:
        raise ValueError("No 'PrivateKey' field found in the BIND file.")

    # Decode the base64-encoded private key (raw scalar)
    raw_scalar = base64.b64decode(private_key_b64)

    # BIND Ed25519 private keys are 32 bytes long
    if len(raw_scalar) != 32:
        raise ValueError("Invalid private key length for Ed25519. Expected 32 bytes.")

    # Load the Ed25519 private key
    private_key = Ed25519PrivateKey.from_private_bytes(raw_scalar)

    return private_key


def load_ed448_private_key_from_bind_file(str_content: str):
    """
    Loads an Ed448 private key from a BIND .private file.
    Returns a cryptography 'Ed448PrivateKey' object.
    """
    private_key_b64 = None

    # Read the .private file line by line
    for line in str_content.split("\n"):
        line = line.strip()
        if line.startswith("PrivateKey:"):
            _, b64_val = line.split(":", 1)
            private_key_b64 = b64_val.strip()
            break

    if not private_key_b64:
        raise ValueError("No 'PrivateKey' field found in the BIND file.")

    # Decode the base64-encoded private key (Ed448 expects 57 bytes)
    raw_private_key = base64.b64decode(private_key_b64)

    if len(raw_private_key) != 57:
        raise ValueError(
            f"Invalid Ed448 private key length: {len(raw_private_key)} bytes (expected 57)."
        )

    # Load the Ed448 private key
    private_key = ed448.Ed448PrivateKey.from_private_bytes(raw_private_key)

    return private_key


def load_private_key_from_bind(str_content: str):
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

    for line in str_content.split("\n"):
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

        # ECDSAP256SHA256
        if algorithm.startswith("13"):
            return (
                load_ecdsa_p256_private_key_from_bind_file(str_content),
                algorithm,
                fields.get("Created"),
                fields.get("Publish"),
                fields.get("Activate"),
            )

        # ECSDAP384SHA384
        if algorithm.startswith("14"):
            return (
                load_ecdsa_p384_private_key_from_bind_file(str_content),
                algorithm,
                fields.get("Created"),
                fields.get("Publish"),
                fields.get("Activate"),
            )

        if algorithm.startswith("15"):
            return (
                load_ed25519_private_key_from_bind_file(str_content),
                algorithm,
                fields.get("Created"),
                fields.get("Publish"),
                fields.get("Activate"),
            )

        if algorithm.startswith("16"):
            return (
                load_ed448_private_key_from_bind_file(str_content),
                algorithm,
                fields.get("Created"),
                fields.get("Publish"),
                fields.get("Activate"),
            )

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
    return (
        private_key,
        algorithm,
        fields.get("Created"),
        fields.get("Publish"),
        fields.get("Activate"),
    )


def generate_bind_private_key(
    algorithm=KeyAlgorithm,
    key_size=2048,
    exponent=65537,
    created: str = datetime.now().strftime("%Y%m%d%H%M%S"),
    publish: str = datetime.now().strftime("%Y%m%d%H%M%S"),
    activate: str = datetime.now().strftime("%Y%m%d%H%M%S"),
):
    """
    Generate a DNSKEY record with different algorithms and parameters.
    algorithm:
      - 8 = RSA/SHA-256
      - 10 = RSA/SHA-512
      - 13 = ECDSA P-256 (SHA-256)
      - 14 = ECDSA P-384 (SHA-384)
      - 15 = Ed25519
      - 16 = Ed448
    key_size: RSA key size : (ignored for ECDSA and EdDSA)
    exponent: Public exponent for RSA (common values: 3, 17, 65537)
    """

    if algorithm in [5, 7, 8, 10]:  # RSA Algorithms
        private_key = rsa.generate_private_key(
            public_exponent=exponent, key_size=key_size
        )

        private_numbers = private_key.private_numbers()

        # Extract public numbers
        public_numbers = private_numbers.public_numbers

        bind_key_info = (
            f"Modulus: {base64_encode_int(public_numbers.n)}\n"
            f"PublicExponent: {base64_encode_int(public_numbers.e)}\n"
            f"PrivateExponent: {base64_encode_int(private_numbers.d)}\n"
            f"Prime1: {base64_encode_int(private_numbers.p)}\n"
            f"Prime2: {base64_encode_int(private_numbers.q)}\n"
            f"Exponent1: {base64_encode_int(private_numbers.dmp1)}\n"
            f"Exponent2: {base64_encode_int(private_numbers.dmq1)}\n"
            f"Coefficient: {base64_encode_int(private_numbers.iqmp)}\n"
        )
        # Construct DNSSEC key format
    # Eliptic curve algorithm
    elif algorithm in [13, 14, 15, 16]:

        if algorithm == 13:  # ECDSA P-256
            private_key = ec.generate_private_key(ec.SECP256R1())
            bind_key_info = f"PrivateKey: {base64_encode_int(private_key.private_numbers().private_value)}\n"
        elif algorithm == 14:  # ECDSA P-384
            private_key = ec.generate_private_key(ec.SECP384R1())
            private_scalar_int = private_key.private_numbers().private_value

            # Convert to 48-byte big-endian
            raw_scalar = private_scalar_int.to_bytes(48, byteorder="big")

            # Base64 encode for BIND .private format
            b64_scalar = base64.b64encode(raw_scalar).decode("ascii")
            bind_key_info = f"PrivateKey: {b64_scalar}\n"

        elif algorithm in [15, 16]:
            if algorithm == 15:  # Ed25519
                private_key = ed25519.Ed25519PrivateKey.generate()
            else:  # Ed448
                private_key = ed448.Ed448PrivateKey.generate()

            bind_key_info = f"PrivateKey: {base64.b64encode((private_key.private_bytes_raw())).decode('utf-8')}\n"

    else:
        raise ValueError(f"Unsupported algorithm {algorithm}")

    bind_header = "Private-key-format: v1.3\n"

    algo_str_description = keyalgo_to_algo_dict.get(algorithm, None)
    if algo_str_description is None:
        raise Exception(f"Unsupported algorithm string description: {algorithm}")

    bind_algo_info = f"Algorithm: {algorithm} ({keyalgo_to_algo_dict[algorithm]})\n"

    bind_time_info = (
        f"Created: {created}\n" f"Publish: {publish}\n" f"Activate: {activate}"
    )

    bind_private_format = bind_header + bind_algo_info + bind_key_info + bind_time_info

    return bind_private_format


class DnssecKey:
    def __init__(self, str_content: str = None):
        """

        :param filepath: Where to find the BIND key.
        """
        self.private_key = None
        self.public_key = None

        self.algorithm = None
        self.str_content = str_content

        if str_content is None:
            raise Exception("str_content cannot be None to load private key")

        priv_k, algo, self.created, self.publish, self.activate = (
            load_private_key_from_bind(str_content)
        )

        self.created = datetime.strptime(self.created, "%Y%m%d%H%M%S")
        self.publish = datetime.strptime(self.publish, "%Y%m%d%H%M%S")
        self.activate = datetime.strptime(self.activate, "%Y%m%d%H%M%S")
        self.private_key = priv_k
        self.algorithm = int(algo)

        self.public_key = self.private_key.public_key()

    @classmethod
    def from_file(cls, filepath: str):

        with open(filepath, "r") as f:
            str_content = f.read()

        return cls(str_content)

    @classmethod
    def generate(
        cls,
        algorithm: KeyAlgorithm,
        keysize=2048,
        exponent=65537,
    ):
        """
        Generate a DNSKEY record with different algorithms and parameters.
        algorithm: As defined in the IntEnum Keyalgorithm
        """

        str_content = generate_bind_private_key(
            algorithm=algorithm, key_size=keysize, exponent=exponent
        )

        return cls(str_content)

    def get_str(self):
        return self.str_content

    def to_file(self, filepath: str):
        with open(filepath, "w") as f:
            f.write(self.str_content)

    def get_private_key_bit(self):
        """Extracts the private key bit value depending on the key type."""
        if isinstance(self.private_key, rsa.RSAPrivateKey):
            return self.private_key.private_numbers().private_key()
        elif isinstance(self.private_key, ec.EllipticCurvePrivateKey):
            return self.private_key.private_numbers().private_key()
        elif isinstance(self.private_key, ed448.Ed448PrivateKey):
            return self.private_key.private_bytes_raw()
        elif isinstance(self.private_key, ed25519.Ed25519PrivateKey):
            return self.private_key.private_bytes_raw()
        else:
            raise ValueError("Unsupported private key type")

    def get_public_key_bit(self):
        """
        Extract the ECDSA P-256 public key in raw format (for DNSKEY).
        """
        if self.algorithm == 13:
            numbers = self.public_key.public_numbers()
            x = numbers.x
            y = numbers.y

            # Convert X and Y to byte arrays (usually 32 bytes for P-256)
            x_bytes = x.to_bytes(32, byteorder="big")
            y_bytes = y.to_bytes(32, byteorder="big")

            # Concatenate X and Y bytes to form the public key
            return x_bytes + y_bytes

        if self.algorithm == 14:
            """
            Extract the ECDSA P-384 public key in raw format (for DNSKEY).
            """
            public_numbers = self.public_key.public_numbers()

            # Convert X and Y coordinates to bytes (48 bytes each for P-384)
            x_bytes = public_numbers.x.to_bytes(48, byteorder="big")
            y_bytes = public_numbers.y.to_bytes(48, byteorder="big")

            # DNSSEC ECDSA public key format: Concatenation of X || Y
            return x_bytes + y_bytes

        if self.algorithm == 15:
            return self.public_key.public_bytes(
                encoding=serialization.Encoding.Raw,  # Ed25519 uses raw encoding
                format=serialization.PublicFormat.Raw,
            )

        if self.algorithm == 16:
            return self.public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )

        if self.algorithm in [5, 7, 8, 10]:

            numbers = self.public_key.public_numbers()

            exponent = numbers.e  # Public exponent
            modulus = numbers.n  # Modulus

            # Encode exponent in DNS format
            if exponent < 256:
                exponent_bytes = bytes([exponent])  # 1 byte
            elif exponent < 65536:
                exponent_bytes = b"\x00" + exponent.to_bytes(2, "big")  # 3 bytes
            else:
                exp_length = (exponent.bit_length() + 7) // 8
                exponent_bytes = bytes([exp_length]) + exponent.to_bytes(
                    exp_length, "big"
                )

            # Encode modulus (big-endian, remove leading zeroes)
            modulus_bytes = modulus.to_bytes((modulus.bit_length() + 7) // 8, "big")

            # Concatenate exponent and modulus
            dnskey_data = exponent_bytes + modulus_bytes

            return dnskey_data

    def get_public_key_b64(self):

        return base64.b64encode(self.get_public_key_bit()).decode("utf-8")


def algo_to_str(algo: int):
    str_algo = str(algo)
    while len(str_algo) < 3:
        str_algo = "0" + str_algo
    return str_algo


def key_id_to_str(key_id: int):
    str_key_tag = str(key_id)
    while len(str_key_tag) < 5:
        str_key_tag = "0" + str_key_tag
    return str_key_tag


def construct_key_file_base_name(fqdn, algo, key_tag):
    return f"K{fqdn}+{algo_to_str(algo)}+{key_id_to_str(key_tag)}"


def key_type_from_file(path) -> KeyFlags:
    with open(path, "r") as f:
        str_content = f.read()
        if "This is a zone-signing key" in str_content:
            return KeyFlags.ZSK

        if "This is a key-signing key" in str_content:
            return KeyFlags.KSK

        raise Exception("Cannot determine key type")


class DnssecKeyInfo:

    def __init__(
        self,
        key: DnssecKey,
        type: KeyFlags,
        revoked=False,
        key_tag=None,
        origin_id: str = "",
    ):
        self.key = key
        self.type = type
        self.revoked = revoked
        self.key_tag = key_tag
        self.origin_id = origin_id

    @classmethod
    def from_file(cls, path, fqdn, algo, key_tag):
        key_basename = construct_key_file_base_name(fqdn, algo, key_tag)
        type = key_type_from_file(path + key_basename + ".key")
        key = DnssecKey.from_file(path + key_basename + ".private")
        return cls(key, type, revoked=False, key_tag=key_tag)

    def get_key(self) -> DnssecKey:
        return self.key

    def get_type(self) -> KeyFlags:
        return self.type

    def get_revoked(self):
        return self.revoked

    def get_dnskey_rdata(self, zone_name, ttl=3600):
        """Create a DNSKEY record for the key."""
        pubkey = self.key

        return make_dnskey_rdata(
            zone_name=zone_name,
            public_key_base64=self.key.get_public_key_b64(),
            algorithm=self.key.algorithm,
            key_flags=self.type if self.get_revoked() is False else self.type | 0x0080,
            ttl=ttl,
            protocol=3,
        )

    def get_ds_record(self, zone_name, digest_algo: DigestAlgorithm, ttl=3600):
        """
        Create a DS record for the key.
        """
        ds_records = dns.dnssec.make_ds(
            name=zone_name,
            key=self.get_dnskey_rdata(zone_name, ttl),
            algorithm=digest_algo,
            validating=True,  # Don't want to get Execption for SHA1 digest
        )

        self.key_tag = ds_records.key_tag
        return ds_records

    def get_rdata(self):
        return DNSKEY(
            rdclass=dns.rdataclass.IN,  # Internet class
            rdtype=dns.rdatatype.DNSKEY,  # RRTYPE 48
            flags=(
                self.get_type() if self.revoked is False else self.get_type() | 0x0080
            ),  # e.g., 256 (ZSK) or 257 (KSK)
            protocol=3,  # Typically 3 for DNSSEC
            algorithm=self.get_key().algorithm,  # e.g. 8 (RSASHA256), 13 (ECDSAP256SHA256), etc....13 => mra, else => 7
            key=self.get_key().get_public_key_bit(),
        )

    def save(self, path, fqdn):
        if not os.path.exists(path + fqdn + "/"):
            os.mkdir(path + fqdn + "/")
        path = os.path.join(path, fqdn) + "/"
        key_tag = self.get_ds_record(fqdn, digest_algo=1).key_tag
        key_name = construct_key_file_base_name(fqdn, self.key.algorithm, key_tag)

        self.write_private(path + key_name + ".private")
        self.write_public(path + key_name + ".key", fqdn, key_tag)

    def write_private(self, path):
        content = self.key.str_content

        with open(path, "w") as f:
            f.write(content)

    def write_public(self, path, fqdn, key_tag):
        content = (
            f"; This is a {"key" if self.type == KeyFlags.KSK else "zone"}-signing key, keyid {key_tag}, for {fqdn}\n"
            f"; Created: {self.key.created.strftime("%Y%m%d%H%M%S")} ({self.key.created.strftime("%a %b %d %H:%M:%S %Y")})\n"
            f"; Publish: {self.key.publish.strftime("%Y%m%d%H%M%S")} ({self.key.publish.strftime("%a %b %d %H:%M:%S %Y")})\n"
            f"; Activate: {self.key.activate.strftime("%Y%m%d%H%M%S")} ({self.key.activate.strftime("%a %b %d %H:%M:%S %Y")})\n"
            f"{fqdn} IN DNSKEY {self.get_rdata()}"
        )
        with open(path, "w") as f:
            f.write(content)

    def load_key(self, fqdn, algo, id):
        pass


def dns_sort_key(domain):
    labels = domain.rstrip(".").split(".")  # Remove trailing dot and split into labels
    return tuple(
        label.lower() for label in reversed(labels)
    )  # Reverse labels for sorting


def generate_nsec3_salt(length=8):  # Length in bytes (8 bytes = 16 hex chars)
    return secrets.token_hex(length).upper()  # Convert to uppercase for DNS compliance


class NSEC3Algo(IntEnum):
    SHA1 = 1


def nsec3_hash(
    domain: Union[dns.name.Name, str],
    salt: Optional[Union[str, bytes]],
    iterations: int,
    algorithm: NSEC3Algo,
) -> str:
    """
    Calculate the NSEC3 hash, according to
    https://tools.ietf.org/html/rfc5155#section-5

    *domain*, a ``dns.name.Name`` or ``str``, the name to hash.

    *salt*, a ``str``, ``bytes``, or ``None``, the hash salt.  If a
    string, it is decoded as a hex string.

    *iterations*, an ``int``, the number of iterations.

    *algorithm*, a ``str`` or ``int``, the hash algorithm.
    The only defined algorithm is SHA1.

    Returns a ``str``, the encoded NSEC3 hash.
    """

    b32_conversion = str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", "0123456789ABCDEFGHIJKLMNOPQRSTUV"
    )

    try:
        if isinstance(algorithm, str):
            algorithm = NSEC3Hash[algorithm.upper()]
    except Exception:
        raise ValueError("Wrong hash algorithm (only SHA1 is supported)")
    # if algorithm != NSEC3Hash.SHA1:
    #     raise ValueError("Wrong hash algorithm (only SHA1 is supported)")

    if salt is None:
        salt_encoded = b""
    elif isinstance(salt, str):
        if len(salt) % 2 == 0:
            salt_encoded = bytes.fromhex(salt)
        else:
            raise ValueError("Invalid salt length")
    else:
        salt_encoded = salt

    if not isinstance(domain, dns.name.Name):
        domain = dns.name.from_text(domain)
    domain_encoded = domain.canonicalize().to_wire()
    assert domain_encoded is not None

    if algorithm == NSEC3Hash.SHA1:
        digest = hashlib.sha1(domain_encoded + salt_encoded).digest()
        for _ in range(iterations):
            digest = hashlib.sha1(digest + salt_encoded).digest()
    elif algorithm == 2:
        digest = hashlib.sha256(domain_encoded + salt_encoded).digest()
        for _ in range(iterations):
            digest = hashlib.sha256(digest + salt_encoded).digest()
    else:
        raise ValueError("Wrong hash algorithm (only SHA1/SHA256 is supported)")

    output = base64.b32encode(digest).decode("utf-8").strip("=")
    output = output.translate(b32_conversion)

    return output


def generate_nsec3_records(
    subdomain_list: List[str],
    iterations: int,
    salt: Optional[Union[str, bytes]],
    hash_algo: NSEC3Algo = NSEC3Algo.SHA1,
    flags: int = 1,
):
    """
    Generates NSEC3 records based on a given zone file and NSEC3PARAM settings.
    Be careful, subdomains are not FQDNS but relatives.
    """
    # Parse the NSEC3PARAM record
    # Sort the names, that should be unique and lowercase.
    original_name = set(subdomain_list)
    names = []
    map_name = dict()
    for n in original_name:
        final_name = n.strip(".").lower()
        map_name[final_name] = n
        names.append(final_name)

    names = sorted(names)

    hashed_names = {}

    for name in names:
        hashed_name = nsec3_hash(str(name), salt, iterations, hash_algo)
        hashed_names[hashed_name] = name

    # Sort hashed names in canonical order
    sorted_hashed_names = sorted(hashed_names.keys())

    nsec3_data = []

    for i in range(len(sorted_hashed_names)):
        current_hash = sorted_hashed_names[i]
        next_hash = sorted_hashed_names[(i + 1) % len(sorted_hashed_names)]

        nsec3_data.append(
            {
                "original_name": map_name[hashed_names[current_hash]],
                "hash": current_hash,
                "next_hash": next_hash,
            }
        )

    return nsec3_data


def generate_nsec_record(subdomain_list: List[str]):
    sorted_names = sorted(subdomain_list, key=dns_sort_key)

    nsec_data = []

    for i, name in enumerate(sorted_names):
        next_name = sorted_names[
            (i + 1) % len(sorted_names)
        ]  # Next name (wraps around)
        nsec_data.append({"original_name": name, "next": next_name})

    return nsec_data


class KeysOption:
    def __init__(
        self,
        algorithm: KeyAlgorithm,
        type: KeyFlags,
        revoked: bool = False,
        origin_id: str = None,
    ):
        self.algorithm = algorithm
        self.type = type
        self.revoked = revoked
        if origin_id is None:

            logger.logger.debug(
                "Cannot find the origin id of the current key in the options"
            )
        self.origin_id = origin_id


class KeysOptions:
    def __init__(self, list: List[KeysOption] = None):
        self.list = list
        if self.list is None:
            self.list = []


class NsecVersion(IntEnum):
    NSEC3 = 0
    NSEC = 1
    NO = 2


class NsecOption:

    def __init__(
        self,
        nsec_version: NsecVersion,
        nsec_digest="",
        nsec_iterations=0,
        salt=None,
        opt_out=0,
    ):

        self.nsec_version = nsec_version
        self.nsec_digest = nsec_digest
        self.nsec_iterations = nsec_iterations
        self.salt = salt
        self.opt_out = opt_out

    @classmethod
    def from_nsec3_record(cls, record):
        splitted_p = record.split(" ")
        algo = splitted_p[0]
        opt_out = splitted_p[1]
        itterations = splitted_p[2]
        salt = splitted_p[3]
        if salt == "-":
            salt = None

        return cls(
            nsec_version=NsecVersion.NSEC3,
            nsec_digest=algo,
            nsec_iterations=itterations,
            opt_out=opt_out,
            salt=salt,
        )

    def __str__(self):
        if self.nsec_version == NsecVersion.NO:
            return "NO NSEC"
        elif self.nsec_version == NsecVersion.NSEC:
            return "NSEC"
        else:
            return (
                f"NSEC3 algo : {self.nsec_digest} opt_out : {self.opt_out} "
                f"itterations : {self.nsec_iterations} salt : {self.salt}"
            )
