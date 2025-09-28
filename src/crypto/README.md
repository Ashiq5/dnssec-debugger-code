# DNSSEC Crypto Package

A comprehensive Python library for DNSSEC key management, signature generation, and NSEC/NSEC3 record creation. This package provides tools for generating, loading, and managing cryptographic keys used in DNSSEC implementations.

## Features

- **Multi-algorithm support**: RSA, ECDSA (P-256, P-384), Ed25519, and Ed448
- **BIND-compatible key formats**: Read and write BIND .private and .key files
- **DNSKEY record generation**: Create properly formatted DNSKEY records
- **DS record generation**: Generate DS records with multiple digest algorithms
- **NSEC/NSEC3 support**: Create NSEC and NSEC3 records for authenticated denial of existence
- **Key management**: Generate, load, and manage DNSSEC keys with proper metadata

## Supported Algorithms

| Algorithm ID | Name |
|-------------|------|
| 5 | RSASHA1 | 
| 7 | NSEC3RSASHA1 | 
| 8 | RSASHA256 | 
| 10 | RSASHA512 | 
| 13 | ECDSAP256SHA256 |
| 14 | ECDSAP384SHA384 |
| 15 | Ed25519 | 
| 16 | Ed448 | 

## Quick Start

### 1. Generate a new DNSSEC key

```python
from dnssec import DnssecKey, DnssecKeyInfo, KeyAlgorithm, KeyFlags

# Generate an Ed25519 ZSK (Zone Signing Key)
zsk = DnssecKey.generate(algorithm=KeyAlgorithm.ED25519)

# Create key info with metadata
zsk_info = DnssecKeyInfo(key=zsk, type=KeyFlags.ZSK)

# Generate an ECDSA P-256 KSK (Key Signing Key)
ksk = DnssecKey.generate(algorithm=KeyAlgorithm.ECDSAP256SHA256)
ksk_info = DnssecKeyInfo(key=ksk, type=KeyFlags.KSK)

print(f"ZSK Algorithm: {zsk.algorithm}")
print(f"KSK Algorithm: {ksk.algorithm}")
```

### 2. Load existing BIND keys

```python
from dnssec import DnssecKey

# Load from BIND private key file
key_content = """Private-key-format: v1.3
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: ....
Created: 20241201120000
Publish: 20241201120000
Activate: 20241201120000"""

key = DnssecKey(key_content)
print(f"Loaded key with algorithm: {key.algorithm}")
```

### 3. Generate DNSKEY and DS records

```python
from dnssec import DigestAlgorithm
import dns.name

zone_name = dns.name.from_text("example.com.")

# Create DNSKEY record
dnskey_rdata = ksk_info.get_dnskey_rdata(zone_name)
print(f"DNSKEY: {zone_name} IN DNSKEY {dnskey_rdata}")

# Create DS record
ds_record = ksk_info.get_ds_record(zone_name, DigestAlgorithm.SHA256)
print(f"DS: {zone_name} IN DS {ds_record}")
```

### 4. Save keys to BIND format files

```python
# Save key pair to BIND format files
zsk_info.save(path="/etc/bind/keys/", fqdn="example.com")
ksk_info.save(path="/etc/bind/keys/", fqdn="example.com")

# This creates files like:
# /etc/bind/keys/example.com/Kexample.com.+013+12345.private
# /etc/bind/keys/example.com/Kexample.com.+013+12345.key
```

## Advanced Usage

### Generate keys with specific parameters

```python
from dnssec import DnssecKey, KeyAlgorithm

# Generate RSA key with custom parameters
rsa_key = DnssecKey.generate(
    algorithm=KeyAlgorithm.RSASHA256,
    keysize=4096,  # 4096-bit RSA key
    exponent=65537
)

# Generate ECDSA P-384 key
ecdsa_key = DnssecKey.generate(algorithm=KeyAlgorithm.ECDSAP384SHA384)
```

### Working with NSEC3 records

```python
from dnssec import generate_nsec3_records, generate_nsec3_salt, NSEC3Algo

# Generate NSEC3 parameters
salt = generate_nsec3_salt(length=8)  # 16 hex characters
iterations = 10

# List of domain names in the zone
subdomains = [
    "example.com",
    "www.example.com", 
    "mail.example.com",
    "ftp.example.com"
]

# Generate NSEC3 records
nsec3_records = generate_nsec3_records(
    subdomain_list=subdomains,
    iterations=iterations,
    salt=salt,
    hash_algo=NSEC3Algo.SHA1,
    flags=1  # Opt-out flag
)

for record in nsec3_records:
    print(f"NSEC3: {record['hash']} -> {record['next_hash']} ({record['original_name']})")
```

### Working with NSEC records

```python
from dnssec import generate_nsec_record

# Generate traditional NSEC records
nsec_records = generate_nsec_record(subdomains)

for record in nsec_records:
    print(f"NSEC: {record['original_name']} -> {record['next']}")
```

### Key algorithm utilities

```python
from dnssec import get_random_algo_not_in_list, key_algo_list_usable

# Get a random algorithm not in the current list
current_algorithms = [13, 15]  # ECDSA P-256 and Ed25519
new_algo = get_random_algo_not_in_list(current_algorithms)
print(f"Suggested new algorithm: {new_algo}")

print(f"All usable algorithms: {key_algo_list_usable}")
```

## Key Management Examples

### Managing key lifecycle

```python
from datetime import datetime, timedelta
from dnssec import DnssecKey, KeyAlgorithm

# Generate key with custom timing
now = datetime.now()
future = now + timedelta(days=30)

key_content = DnssecKey.generate_bind_private_key(
    algorithm=KeyAlgorithm.ED25519,
    created=now.strftime("%Y%m%d%H%M%S"),
    publish=now.strftime("%Y%m%d%H%M%S"), 
    activate=future.strftime("%Y%m%d%H%M%S")
)

key = DnssecKey(key_content)
print(f"Key created: {key.created}")
print(f"Key published: {key.publish}")
print(f"Key activated: {key.activate}")
```

### Working with revoked keys

```python
from dnssec import DnssecKeyInfo, KeyFlags

# Create a revoked key
revoked_ksk = DnssecKeyInfo(
    key=ksk, 
    type=KeyFlags.KSK, 
    revoked=True
)

# The DNSKEY record will have the revoked flag set
dnskey_revoked = revoked_ksk.get_dnskey_rdata(zone_name)
print(f"Revoked DNSKEY flags: {dnskey_revoked.flags}")  # Will show 385 (257 | 128)
```

## Configuration Classes

### KeysOption and KeysOptions

```python
from dnssec import KeysOption, KeysOptions, KeyAlgorithm, KeyFlags

# Define key configuration
key_config = KeysOption(
    algorithm=KeyAlgorithm.ED25519,
    type=KeyFlags.ZSK,
    revoked=False,
    origin_id="primary-zsk"
)

# Multiple key configurations
keys_config = KeysOptions([
    KeysOption(KeyAlgorithm.ED25519, KeyFlags.ZSK, origin_id="zsk-1"),
    KeysOption(KeyAlgorithm.ECDSAP256SHA256, KeyFlags.KSK, origin_id="ksk-1")
])
```

### NSEC Configuration

```python
from dnssec import NsecOption, NsecVersion

# NSEC3 configuration
nsec3_config = NsecOption(
    nsec_version=NsecVersion.NSEC3,
    nsec_digest="1",      # SHA-1
    nsec_iterations=10,
    salt="AABBCCDD",
    opt_out=0
)

# NSEC configuration
nsec_config = NsecOption(nsec_version=NsecVersion.NSEC)

# No NSEC
no_nsec_config = NsecOption(nsec_version=NsecVersion.NO)

print(nsec3_config)  # "NSEC3 algo : 1 opt_out : 0 iterations : 10 salt : AABBCCDD"
```

## Error Handling

```python
from dnssec import DnssecKey, KeyAlgorithm

try:
    # Attempt to load invalid key content
    invalid_key = DnssecKey("invalid content")
except ValueError as e:
    print(f"Key loading failed: {e}")

try:
    # Try to get algorithm not in list when none available
    from dnssec import get_random_algo_not_in_list, key_algo_list_usable
    new_algo = get_random_algo_not_in_list(key_algo_list_usable)
except Exception as e:
    print(f"No available algorithms: {e}")
```

## API Reference

### Core Classes

- **`DnssecKey`**: Main class for DNSSEC key operations
- **`DnssecKeyInfo`**: Key metadata and operations wrapper
- **`KeyAlgorithm`**: Enum of supported DNSSEC algorithms
- **`KeyFlags`**: Key type flags (ZSK=256, KSK=257)
- **`DigestAlgorithm`**: DS record digest algorithms

### Utility Functions

- **`generate_nsec3_records()`**: Generate NSEC3 records for a zone
- **`generate_nsec_record()`**: Generate NSEC records for a zone
- **`generate_nsec3_salt()`**: Generate cryptographically secure NSEC3 salt
- **`nsec3_hash()`**: Calculate NSEC3 hash for a domain name