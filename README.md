# ZReplicator & DFixer

This repository contains the codebase and the artifact generation (table 6 and 7) of the paper : **Decoding DNSSEC Errors at Scale: An Automated DNSSEC Error Resolution Framework using Insights from DNSViz Logs**

It contains :
- The code and the instruction to generate table 6 and 7 of the paper in the folder **paper_artifacts**
- The source code of all the packages written for our experiment in the **src/** folder.
- Everything needed to run the measurement container in the **Docker** folder.
- The **docker-compose.yaml** file to build and run the container.
- **main.py** which is a simplified version of our experiment utilities. 

```text
.
├── main.py
├── docker-compose.yaml
├── Docker
│   └── domain_keys
├── paper_artifacts
│   └── generated
├── src
│   ├── crypto (DNSSEC cryptographic utility package)
│   ├── DFixer (main DNSSEC error detection and resolution tool)
│   ├── domaingenerator (Python classes for domain name structures)
│   ├── grokreader (utilities for extracting DNSViz JSON file information)
│   ├── utils (shared utility functions for the project)
│   └── ZReplicator (domain replication package using grokreader parameters)
```

## Run DFixer / ZReplicator



```
docker compose up --build
```
Run the pipeline for a domain name (e.g. dnssec-failed.org)
```
docker exec -it  ErroneousZoneGeneration /usr/bin/python3 /data/ErroneousZoneGeneration/main.py --resolve dnssec-failed.org
```

## Containerized Environment

We opted for a single Docker container setup since our experiment requires managing two Authoritative Name Servers. 
The container runs two BIND instances that can be controlled via RNDC on ports 953 and 954.
All necessary python dependencies are pre-installed in the container for seamless experiment execution.


## Limitations and Considerations
### Dataset Restrictions
The original DNSViz dataset cannot be publicly shared due to privacy and licensing constraints. Our implementation has been adapted accordingly:

- **Format Dependency**: The code was originally designed for the specific DNSViz dataset format
- **Public Adaptation** : The main.py file has been modified for public release while maintaining core functionality
- **Legacy Code**: Some remnants of the original implementation may be present in main.py

### System Requirements

- Docker and Docker Compose
- Sufficient disk space for container images and experimental data
- Network access for DNS resolution

