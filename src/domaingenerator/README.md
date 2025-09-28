# Domain Generator

A Python package for generating DNS domains, zone files, and BIND configuration files with DNSSEC support. This tool is designed for testing DNS implementations, creating test environments, and generating complex domain structures with various DNS record types.

## Features

- **Domain Generation**: Create complex domain structures with subdomains
- **DNS Record Types**: Support for A, AAAA, TXT, NS, SOA, DNSKEY, DS records
- **DNSSEC Support**: Generate signed zones with KSK/ZSK key pairs
- **NSEC/NSEC3**: Support for both NSEC and NSEC3 denial of existence
- **Zone File Generation**: Create BIND-compatible zone files
- **Named Configuration**: Generate BIND named.conf entries
- **Flexible Configuration**: Customizable TTL, record counts, and domain parameters


## Dependencies

- `dnspython`
- `faker`
- `cryptography` (for DNSSEC operations)
- `config` from the main `src/` folder (see main README.md)

## Quick Start

### Basic Domain Generation

```python
from domaingenerator import Domain

# Generate a simple domain with 3 subdomains
domain = Domain.generate(
    domain="example.com.",
    nb_subdomain=3,
    additional_record=True
)

print(domain)
```

### Creating a Zone File

```python
from domaingenerator import Domain
from domaingenerator.zonefile_generator import ZonefileGenerator
from domaingenerator.rrtype_gen import SOAContent

# Create a domain
domain = Domain.generate("test.com.", nb_subdomain=2)

# Add SOA record
soa = SOAContent(
    primary_ns="ns1.test.com.",
    admin_email="admin.test.com."
)
domain.set_soa(soa)

# Generate zone file
generator = ZonefileGenerator(domain, ttl=86400)
generator.to_file("/tmp/zones/", signed=False)
```

### DNSSEC Signing

```python
from domaingenerator import Domain
from domaingenerator.zonefile_generator import ZonefileGenerator
from crypto.dnssec import DnssecKeyInfo, KeyFlags

# Create domain
domain = Domain.generate("secure.com.", nb_subdomain=1)

# Add DNSSEC keys (assuming you have key generation functions)
ksk = DnssecKeyInfo(key_type=KeyFlags.KSK)  # Your KSK
zsk = DnssecKeyInfo(key_type=KeyFlags.ZSK)  # Your ZSK

domain.add_key(ksk)
domain.add_key(zsk)

# Generate and sign zone file
generator = ZonefileGenerator(domain)
generator.sign()  # Sign the zone
generator.to_file("/tmp/zones/", signed=True)
```

## Advanced Examples

### Custom Domain Structure

```python
from domaingenerator import Domain, DomainInstruction, DomainSpecificParameters

# Define specific subdomain parameters
custom_params = [
    DomainSpecificParameters(
        DomainInstruction.ADD_SUBDOMAIN,
        {
            "subdomain": "mail",
            "nb_subdomains": 0,
            "additional_records": True
        }
    ),
    DomainSpecificParameters(
        DomainInstruction.REMOVE_A_RECORD,
        {"subdomain": "internal"}
    )
]

# Generate domain with custom parameters
domain = Domain.generate(
    domain="company.com.",
    nb_subdomain=5,
    additional_record=True,
    wildcard_subdomain=True,
    specific_parameters=custom_params
)
```

### NSEC3 Configuration

```python
from domaingenerator.zonefile_generator import ZonefileGenerator
from crypto.dnssec import NSEC3Algo

# Create domain and generator
domain = Domain.generate("example.org.", nb_subdomain=3)
generator = ZonefileGenerator(domain)

# Add NSEC3 records
generator.add_nsec3_domains(
    iterations=10,
    salt="ABCDEF123456",
    hash_algo=NSEC3Algo.SHA1,
    flags=0,
    ttl=3600
)
```

### Generate BIND Configuration

```python
from domaingenerator.namedconf import NamedConf
from pathlib import Path

# Create named.conf for multiple domains
domains = ["example.com.", "test.org.", "demo.net."]
named_conf = NamedConf(
    domains=domains,
    path=Path("/etc/bind/zones/")
)

# Generate master configuration
config_content = named_conf.configuration(type="master")
print(config_content)

# Write to file
named_conf.write(Path("/etc/bind/named.conf.local"), type="master")
```

### Batch Domain Generation

```python
from domaingenerator import Domain
from domaingenerator.zonefile_generator import ZonefileGenerator

# Generate multiple domains for testing
domains_to_create = [
    {"name": "test1.com.", "subdomains": 3},
    {"name": "test2.com.", "subdomains": 5},
    {"name": "test3.com.", "subdomains": 2}
]

for domain_config in domains_to_create:
    # Create domain
    domain = Domain.generate(
        domain_config["name"],
        nb_subdomain=domain_config["subdomains"],
        additional_record=True
    )
    
    # Generate zone file
    generator = ZonefileGenerator(domain, ttl=3600)
    generator.to_file("/tmp/test_zones/")
    
    print(f"Generated zone file for {domain_config['name']}")
```

## API Reference

### Domain Class

#### `Domain.generate(domain, nb_subdomain, additional_record=True, wildcard_subdomain=False, specific_parameters=None)`

Generate a new domain with specified parameters.

**Parameters:**
- `domain` (str): Fully qualified domain name (must end with '.')
- `nb_subdomain` (int): Number of subdomains to generate
- `additional_record` (bool): Include A, AAAA, and TXT records
- `wildcard_subdomain` (bool): Include wildcard subdomain
- `specific_parameters` (List[DomainSpecificParameters]): Custom domain modifications

#### Key Methods:
- `add_key(key)`: Add DNSSEC key
- `set_ns(nameservers)`: Set nameserver records
- `set_soa(soa)`: Set SOA record
- `to_dict()`: Convert to dictionary format
- `is_delegated()`: Check if domain is delegated

### ZonefileGenerator Class

#### `ZonefileGenerator(domain, ttl=86400, nameservers=None)`

Generate DNS zone files from Domain objects.

**Key Methods:**
- `sign()`: Sign the zone with DNSSEC
- `add_nsec_domains()`: Add NSEC records
- `add_nsec3_domains()`: Add NSEC3 records
- `to_file(path, signed=False)`: Write zone file to disk
- `zonefile_text()`: Get zone file as text

### Record Types

The package supports various DNS record types through the `rrtype_gen` module:

- `AContent`: IPv4 addresses
- `AAAAContent`: IPv6 addresses  
- `TXTContent`: Text records
- `NSContent`: Name server records
- `SOAContent`: Start of Authority records
- `EMPTYContent`: Placeholder records

## Configuration

The package uses a `config.py` file for default values:

```python
# Example configuration values
TTL = 86400
DEFAULT_INCEPTION = "20240101000000"
DEFAULT_EXPIRATION = "20241231235959"
ROOT_NS = ["ns1.example.com.", "ns2.example.com."]
```

## Use Cases

- **DNS Testing**: Generate test domains for DNS server validation
- **Performance Testing**: Create large domain structures for load testing
- **DNSSEC Testing**: Generate signed zones for DNSSEC implementation testing
- **Development**: Create realistic DNS data for application development
- **Education**: Generate examples for DNS training and documentation