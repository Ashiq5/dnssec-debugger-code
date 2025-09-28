# DFixer

A Python package for identifying, analyzing, and automatically fixing DNSSEC (Domain Name System Security Extensions) configuration errors in DNS zones.

## Overview

DFixer is a comprehensive DNSSEC error detection and remediation tool that analyzes DNS zone configurations, identifies security-related issues, and provides automated fixes. It works by processing DNSViz analysis data to detect DNSSEC validation errors and generates corrective instructions that can be automatically applied to resolve these issues.

## Features

- **Error Identification**: Detects various DNSSEC-related errors in DNS zone configurations
- **Meta-parameter Analysis**: Extracts signing parameters, key configurations, and NSEC options from DNS analysis data
- **Automated Fix Generation**: Creates specific instructions to remediate identified DNSSEC errors
- **Iterative Fix Application**: Applies fixes iteratively until errors are resolved or a stable state is reached
- **Pretty Printing**: Provides human-readable output of fix instructions for debugging and verification

## Core Components

### Main Modules

- **`identify_meta_parameters`**: Analyzes DNS data to extract DNSSEC configuration parameters
- **`get_instructions`**: Generates fix instructions based on identified zone issues
- **`execute_instructions`**: Applies the generated fixes to the DNS configuration
- **`find_errors_in_analysis`**: Parses analysis data to identify DNSSEC-related errors
- **`_pretty_print`**: Formats instructions for readable output

### Key Functions

#### `identify_meta_parameters(id_, analysis, psl, grok_data)`
Extracts comprehensive DNSSEC parameters from DNS analysis data.

**Parameters:**
- `id_`: Unique identifier for the analysis
- `analysis`: DNS analysis data (typically from DNSViz)
- `psl`: PublicSuffixList instance for domain parsing
- `grok_data`: GrokData object containing signing information

**Returns:** Tuple containing:
- Case name
- Parent domain information
- DNSSEC errors
- Parent/child DNSKEY lists
- NSEC options
- Name server configurations
- Signing parameters
- DS record mappings

#### `find_errors_in_analysis(analysis, psl)`
Identifies DNSSEC validation errors in the analysis data.

**Parameters:**
- `analysis`: DNS analysis JSON data
- `psl`: PublicSuffixList instance

**Returns:** Dictionary mapping domains to their associated errors

#### `get_instructions(zone_name)`
Generates fix instructions for a specific DNS zone.

**Parameters:**
- `zone_name`: The DNS zone requiring fixes

**Returns:** List of instructions to fix identified issues (or None if no fixes needed)

#### `execute_instructions(instructions)`
Applies the generated fix instructions to the DNS configuration.

**Parameters:**
- `instructions`: List of fix instructions from `get_instructions()`

**Raises:** Exception if instruction execution fails

## Usage Example

```python
import json
from publicsuffixlist import PublicSuffixList
from GrokParam import GrokData
from DFixer import (
    identify_meta_parameters,
    find_errors_in_analysis,
    get_instructions,
    execute_instructions,
    _pretty_print
)

# Load DNS analysis data
with open('dns_analysis.json', 'r') as f:
    analysis_data = json.load(f)

# Initialize required components
psl = PublicSuffixList()
grok_data = GrokData(analysis_line)

# Step 1: Find errors in the analysis
dom2err = find_errors_in_analysis(analysis_data, psl=psl)

# Step 2: Identify zone name
zone_name = identify_zone_name(analysis_data)

# Step 3: Extract meta parameters for DNSSEC configuration
params = identify_meta_parameters(
    id_="analysis_001",
    analysis=analysis_data,
    psl=psl,
    grok_data=grok_data
)

# Check for exceptions
if params in ["Exception!!!Probably Delegated", "Exception!!!Unsigned Parent Zone"]:
    print(f"Cannot process: {params}")
    exit(1)

# Step 4: Generate fix instructions
instructions = get_instructions(zone_name)

if instructions:
    # Step 5: Display instructions (optional)
    _pretty_print(instructions)
    
    # Step 6: Execute fixes
    try:
        execute_instructions(instructions)
        print("Fixes applied successfully")
    except Exception as e:
        print(f"Failed to apply fixes: {e}")
```

## Iterative Fix Application

DFixer supports iterative fixing for complex DNSSEC issues that may require multiple rounds of corrections:

```python
max_iterations = 10
iteration = 0
errors_remain = True

while errors_remain and iteration < max_iterations:
    # Get current errors
    instructions = get_instructions(zone_name)
    
    if not instructions:
        errors_remain = False
        break
    
    # Apply fixes
    execute_instructions(instructions)
    
    # Re-analyze to check if errors are resolved
    # (Re-run DNS validation here)
    
    iteration += 1
```

## Error Types

DFixer handles various DNSSEC-related error codes, including:
- Key validation errors
- Signature validation failures
- DS record mismatches
- NSEC/NSEC3 chain errors
- Timing-related issues (inception/expiration)

## Integration with DNS Infrastructure

DFixer is designed to work with:
- **DNSViz**: For DNS/DNSSEC analysis and validation
- **BIND**: For DNS server configuration updates
- **Zone file management**: Automatic zone file generation and updates

## Output Format

DFixer operations typically produce JSON output containing:
```json
{
    "zone_name": "example.com",
    "intended_errcodes": ["DNSKEY_MISSING", "RRSIG_EXPIRED"],
    "generated_errcodes": ["DNSKEY_MISSING"],
    "fix_transition_errcodes": [
        {
            "errors_before_fix": ["DNSKEY_MISSING", "RRSIG_EXPIRED"],
            "errors_after_fix": ["RRSIG_EXPIRED"],
            "fixes": [
                {
                    "domain": "example.com",
                    "instructions": ["add_dnskey", "resign_zone"]
                }
            ]
        }
    ],
    "fix_iterations": 2
}
```

## Dependencies

- `publicsuffixlist`: For domain parsing and validation
- `GrokParam`: For parameter extraction from DNS data
- `ZReplicator`: For zone replication and management
- DNSViz: For DNS/DNSSEC analysis (external tool)

## Error Handling

DFixer includes comprehensive error handling for:
- Delegated zones (returns "Exception!!!Probably Delegated")
- Unsigned parent zones (returns "Exception!!!Unsigned Parent Zone")
- Execution failures during fix application