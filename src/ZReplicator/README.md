# ZReplicator - DNSSEC Error Reproduction Framework

ZReplicator is a specialized Python package that generates DNS zones and zone files with specific DNSSEC configurations and intentional errors. It serves as the domain generation engine within a larger DNSSEC testing ecosystem, taking structured input parameters and producing corresponding DNS zones that replicate real-world DNSSEC validation scenarios.

**Please note:  ZReplicator is a research prototype and may be difficult to understand or use as a standalone library.  ** 
We apologize for any complexity. 
This code was developed for academic research purposes rather than as a professional software package. If you wish to use ZReplicator, we strongly recommend examining the implementation in main.py to understand the expected usage patterns and integration approach.

## Core Purpose

ZReplicator acts as the **zone generation backend** that:
- **Receives structured input** containing domain parameters, key configurations, NSEC options, and error specifications
- **Generates complete DNS hierarchies** with parent-child-grandchild domain relationships
- **Applies DNSSEC configurations** including key generation, signing parameters, and denial-of-existence mechanisms
- **Injects specific errors** at precise points in the zone generation process
- **Outputs ready-to-deploy zone files** and BIND configurations for testing environments

The package is designed to work seamlessly with analysis tools that extract domain parameters from real-world DNSSEC failures.


## Core Functions

### `new_domain_use_case()`

Creates a single domain with specified parameters.

**Parameters:**
- `subdomain` (str): Subdomain name (e.g., "test")
- `parent` (str): Parent domain FQDN (e.g., "example.com")
- `keys_options` (List[KeysOption]): List of DNSSEC keys to generate
- `nb_subdomains` (int, default=0): Number of child subdomains to create
- `ns` (List[str], optional): Name servers for this domain
- `signed` (bool, default=True): Whether to generate DNSSEC keys
- `wildcard_subdomain` (bool, default=False): Include wildcard records
- `domain_specific_parameters` (List[DomainSpecificParameters], optional): Custom record types

**Returns:**
- `tuple`: (Domain object, FQDN string)

**Example:**
```python
from ZReplicator.util import new_domain_use_case
from crypto.dnssec import KeysOption, KeyFlags, KeyAlgorithm

keys = [
    KeysOption(algorithm=KeyAlgorithm.RSASHA256, type=KeyFlags.KSK),
    KeysOption(algorithm=KeyAlgorithm.RSASHA256, type=KeyFlags.ZSK)
]

domain, fqdn = new_domain_use_case(
    subdomain="test",
    parent="example.com",
    keys_options=keys,
    nb_subdomains=3,
    ns=["ns1.example.com", "ns2.example.com"]
)
# Returns: (Domain object, "test.example.com")
```

### `make_one_new_case()`

Creates a complete test case with parent-child domain hierarchy and applies DNSSEC errors.

**Parameters:**
- `case_name` (str): Unique identifier for this test case
- `parent` (str): Parent domain FQDN
- `dnssec_errors` (DnssecErrors): Errors to inject into the domains
- `parent_key_list` (KeysOptions): DNSSEC keys for parent domain
- `children_key_list` (KeysOptions): DNSSEC keys for child domain
- `parent_nsec_option` (NsecOption): NSEC/NSEC3 configuration for parent
- `children_nsec_option` (NsecOption): NSEC/NSEC3 configuration for child
- `parent_ns` (List[str]): Name servers for parent domain
- `child_ns` (List[str]): Name servers for child domain
- `inception` (str, optional): RRSIG inception time (YYYYMMDDHHMMSS)
- `expiration` (str, optional): RRSIG expiration time (YYYYMMDDHHMMSS)
- `is_children_signed` (bool, default=True): Whether child domain is DNSSEC signed
- `wildcard_subdomain` (bool, default=False): Include wildcard records
- `nb_subdomains_children` (int, default=3): Number of subdomains under child
- `parent_use_case` (Domain, optional): Pre-existing parent domain
- `children_use_case` (Domain, optional): Pre-existing child domain
- `parent_specific_parameters` (List[DomainSpecificParameters], optional): Custom parent records
- `children_specific_parameters` (List[DomainSpecificParameters], optional): Custom child records
- `grand_children_use_case` (Domain, optional): Pre-existing grandchild domain
- `signing_parameters` (SigningParameters, optional): Custom signing parameters
- `ds_map` (dict, optional): DS record mapping

**Returns:**
- `list`: [zone_parent, zone_children, zone_unsigned_children, parent_use_case, children_use_case, unsigned_children_use_case, grand_children_use_case, zone_grand_children]

Where:
- `zone_parent`: ZonefileGenerator for parent domain
- `zone_children`: ZonefileGenerator for child domain  
- `zone_unsigned_children`: ZonefileGenerator for unsigned child (if created)
- `parent_use_case`: Domain object for parent
- `children_use_case`: Domain object for child
- `unsigned_children_use_case`: Domain object for unsigned child (if created)
- `grand_children_use_case`: Domain object for grandchild
- `zone_grand_children`: ZonefileGenerator for grandchild domain

**Example:**
```python
from ZReplicator.util import make_one_new_case
from ZReplicator import DnssecError, DnssecErrorType, DnssecErrors, DnssecPriority

# Define the error scenario
errors = DnssecErrors([
    DnssecError(DnssecErrorType.SIGNATURE_INVALID, DnssecPriority.AFTER_SIGNATURE),
    DnssecError(DnssecErrorType.REMOVE_ONE_KSK, DnssecPriority.AFTER_DOMAIN_CREATION)
])

# Generate complete test case
zones = make_one_new_case(
    case_name="multi-error-test",
    parent="example.com",
    dnssec_errors=errors,
    parent_key_list=parent_keys,
    children_key_list=children_keys,
    parent_nsec_option=NsecOption(NsecVersion.NSEC3, salt="ABCDEF", nsec_iterations=1),
    children_nsec_option=NsecOption(NsecVersion.NSEC, salt="", nsec_iterations=0),
    parent_ns=["ns1.example.com", "ns2.example.com"],
    child_ns=["ns1.child.example.com", "ns2.child.example.com"],
    inception="20240101000000",
    expiration="20241231235959",
    nb_subdomains_children=5
)

# Extract the generated components
zone_parent, zone_children, zone_unsigned, parent_domain, child_domain, unsigned_domain, grandchild_domain, zone_grandchild = zones

print(f"Parent domain: {parent_domain.fqdn}")
print(f"Child domain: {child_domain.fqdn}")  
print(f"Grandchild domain: {grandchild_domain.fqdn}")
print(f"Applied errors: {[err.error_type for err in errors.errors]}")
```

## Error Priority Levels

ZReplicator applies errors at different stages of the zone generation process:

1. **AFTER_DOMAIN_CREATION**: Applied immediately after domain objects are created
2. **AFTER_ZONEFILE_CREATION**: Applied after initial zone file generation
3. **AFTER_NSEC**: Applied after NSEC/NSEC3 records are added
4. **AFTER_SIGNATURE**: Applied after zone signing
5. **AFTER_PARENT_ZONEFILE_CREATION**: Applied to parent zone operations
6. **REDO_WHOLE_PROCESS**: Triggers a complete regeneration
7. **LAST_AFTER_SIGNATURE**: Final modifications after signing

## Configuration

Set up your environment with the required configuration (see main README.md)
