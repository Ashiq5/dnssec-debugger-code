# Grokreader

A Python package for parsing and analyzing DNS/DNSSEC validation results
that is produce by dnsviz grok https://github.com/dnsviz/dnsviz

Grokreader processes the grok file JSON-formatted DNS query results and provides structured access to DNS records, DNSSEC validation status, errors, and warnings.

## Installation

```bash
pip install grokreader
```

## Quick Start

```python
from grokreader import GrokData

# Load DNS analysis results from JSON
with open('dns_results.json', 'r') as f:
    json_line = f.read()

# Parse the data
grok_data = GrokData(json_line)

# Get all errors
errors = grok_data.get_errors()
for error in errors:
    print(f"Error: {error.code} - {error.description}")
    print(f"Location: {error.get_path().parent_path}")

# Get DNSSEC key information
for fqdn_info in grok_data.GrokFqdnInfos:
    print(f"Domain: {fqdn_info.name}")
    key_map = fqdn_info.get_key_map()
    print(f"DNSSEC Keys: {key_map}")
```

## Core Classes

### GrokData
The main entry point for parsing DNS analysis results.

```python
grok_data = GrokData(json_line)

# Access parsed FQDN information
for fqdn in grok_data.GrokFqdnInfos:
    print(f"Domain: {fqdn.name}")
    print(f"Status: {fqdn.status}")

# Get error summary
errors = grok_data.get_errors()
error_codes = grok_data.error_set()
```

### GrokFqdnInfo
Represents DNS information for a specific Fully Qualified Domain Name.

```python
fqdn_info = grok_data.GrokFqdnInfos[0]

# Access zone information
if fqdn_info.zone_info:
    print("This FQDN has authoritative zone data")

# Access delegation information
if fqdn_info.delegation:
    ds_records = fqdn_info.delegation.get_ds_map()
    print(f"DS Records: {ds_records}")

# Access DNS queries and responses
for query in fqdn_info.queries:
    print(f"Query: {query.qname}")
    for answer in query.answers:
        print(f"Answer: {answer.type} - {answer.rdata}")
```

### GrokQuery
Represents a DNS query and its responses.

```python
query = fqdn_info.queries[0]

# Check for different response types
if query.answers:
    for answer in query.answers:
        print(f"Answer: {answer.name} {answer.type} {answer.rdatas}")

if query.nodata:
    print("NODATA response received")

if query.nxdomain:
    print("NXDOMAIN response received")
```

### Error Handling

```python
# Get all errors across all domains
all_errors = grok_data.get_errors()

# Get errors organized by domain
domain_errors = grok_data.dom2err()

# Get error codes for a specific zone
zone_name = grok_data.identify_zone_name()
zone_errors = grok_data.get_errcodes_for_zone(zone_name)
```

## DNSSEC Analysis

### Key Management
```python
# Get DNSSEC signing information
signing_info = grok_data.get_signing_information()
print(f"DNSKEY signers: {signing_info['DNSKEY']}")
print(f"Other record signers: {signing_info['OTHER']}")

# Analyze DS records
for fqdn in grok_data.GrokFqdnInfos:
    ds_map = fqdn.get_ds_map()
    if ds_map:
        for ds in ds_map:
            print(f"DS: Algorithm {ds['algorithm']}, Key Tag {ds['key_tag']}")
```

### Denial of Existence
```python
# Check denial of existence parameters
doe_params = grok_data.get_denial_of_existence_parameters()
if doe_params:
    print(f"Denial of existence method: {doe_params}")
```

## Zone Analysis

```python
# Identify the main zone
zone_name = grok_data.identify_zone_name()
parent_zone = grok_data.identify_parent_zone()

print(f"Zone: {zone_name}")
print(f"Parent Zone: {parent_zone}")

# Get zone object
zone_fqdn = grok_data.get_fqdn_object_of_zone_name()
if zone_fqdn and zone_fqdn.zone_info:
    for server in zone_fqdn.zone_info.servers:
        print(f"Name Server: {server.server_name}")
        print(f"  Auth IPs: {server.auth}")
        print(f"  Glue IPs: {server.glue}")
```

## Error Categories

Common error codes you might encounter:

- `SERVER_UNRESPONSIVE_UDP`: DNS server not responding over UDP
- `ALGORITHM_NOT_RECOMMENDED`: Use of deprecated DNSSEC algorithms
- `DIGEST_ALGORITHM_PROHIBITED`: Use of prohibited digest algorithms
- `NONZERO_NSEC3_ITERATION_COUNT`: NSEC3 iteration count should be 0
- `NONEMPTY_NSEC3_SALT`: NSEC3 salt should be empty

## Input Format

Grokreader expects JSON input in a specific format. The JSON should contain DNS query results with DNSSEC validation information. Example structure:

```json
[
  "query_id",
  [
    "200",
    {
      "example.com.": {
        "status": "NOERROR",
        "queries": {
          "example.com./IN/A": {
            "answer": [...]
          }
        },
        "dnskey": [...],
        "delegation": {...}
      }
    }
  ]
]
```

## Debugging

Enable debug mode to catch missing keys in the dataset:

```python
import grokreader
grokreader.DEBUG = True
```

When debug mode is enabled, the library will raise exceptions if unexpected keys are found in the JSON data, helping identify parsing issues.