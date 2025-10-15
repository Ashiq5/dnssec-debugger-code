import dns.zone
from dns import rdataclass, rdatatype

from config import *
from crypto.dnssec import (
    DigestAlgorithm,
    KeyFlags,
    NSEC3Algo,
    generate_nsec3_records,
    generate_nsec3_salt,
    generate_nsec_record,
)
from utils import convert_to_epoch_time
from utils.logging_utils import logger
from .domain_generator import Domain
from .rrtype_gen import RRtypeGen, SOAContent


class SigningParameters:
    def __init__(self, signer: dict):
        self.DNSKEY = signer.get("DNSKEY", [])
        self.OTHER = signer.get("OTHER", [])


class ZonefileGenerator:
    """Class for generating DNS zone files."""

    def __init__(self, domain: Domain, ttl: int = 86400, nameservers=None, ds_map=None):
        if nameservers is None:
            nameservers = ROOT_NS
        self.domain_class = domain
        self.ttl = ttl
        self.fqdn = domain.get_fqdn()
        self.zone = dns.zone.Zone(self.fqdn, relativize=False)
        self.nameservers = nameservers
        self.sub_zone = []
        self.ds_map = ds_map
        if self.ds_map is None:
            self.ds_map = dict()
        self.import_from_domain(domain)

    def import_from_domain(self, domain: Domain):
        if domain.SOA is not None:
            self.add_soa(domain.SOA)

        self.add_from_text(domain.get_fqdn(), domain.A)
        self.add_from_text(domain.get_fqdn(), domain.AAAA)
        self.add_from_text(domain.get_fqdn(), domain.TXT)
        self.add_ns(self.fqdn, self.nameservers)
        if domain.DNSKEY is not None:
            self.add_dnskey()

        for sub in domain.get_subdomains():
            if not sub.is_delegated():
                self.import_from_domain(sub)

            else:
                self.add_ns(sub.get_fqdn(), self.nameservers)
                self.add_ds(sub)

    def sign(
        self,
        ttl: int = TTL,
        inception: str = DEFAULT_INCEPTION,
        expiration: str = DEFAULT_EXPIRATION,
        signing_parameters: SigningParameters = None,
    ):
        # Sign the DNSKEY record with the KSK
        ksks = [k for k in self.domain_class.keys if k.get_type() == KeyFlags.KSK]
        zsks = [k for k in self.domain_class.keys if k.get_type() == KeyFlags.ZSK]
        if len(zsks) == 0:
            zsks = ksks

        for name, nodes in self.zone.nodes.items():

            for r in nodes.rdatasets:
                rdataset = dns.rdataset.Rdataset(
                    dns.rdataclass.IN, dns.rdatatype.RRSIG, ttl=ttl
                )
                # DNSKEYS are signed by Key Signing Keys
                if r.rdtype == rdatatype.DNSKEY:
                    for KSK in ksks + zsks:
                        if (
                            signing_parameters is not None
                            and KSK.origin_id != "ERROR_HANDLER"
                        ):
                            if KSK.origin_id not in signing_parameters.DNSKEY:
                                logger.logger.debug(
                                    "Skipping a Key, was not in the origin one"
                                )
                                continue

                        rrset = dns.rrset.from_rdata_list(name, r.ttl, r)
                        rrsig = dns.dnssec.sign(
                            rrset=rrset,
                            private_key=KSK.get_key().get_private_key_bit(),
                            signer=self.fqdn,
                            inception=convert_to_epoch_time(inception),
                            expiration=convert_to_epoch_time(expiration),
                            dnskey=KSK.get_rdata(),
                            # rrsig_ttl=None,  #  TODO: for otert: rrsig_ttl = 20 (< original ttl); others: None
                            verify=False,
                            origin=dns.name.Name(self.fqdn),
                            # labels=None  # only for lex = 5; for others use None
                        )
                        rdataset.add(rrsig)
                elif r.rdtype != rdatatype.RRSIG:
                    for ZSK in zsks:
                        if len(r) == 0:
                            continue

                        if (
                            signing_parameters is not None
                            and ZSK.origin_id != "ERROR_HANDLER"
                        ):
                            if ZSK.origin_id not in signing_parameters.OTHER:
                                logger.logger.debug(
                                    "Skipping a Key for other record, was not in the origin one"
                                )
                                continue

                        rrset = dns.rrset.from_rdata_list(name, r.ttl, r)

                        try:
                            rrsig = dns.dnssec.sign(
                                rrset=rrset,
                                private_key=ZSK.get_key().get_private_key_bit(),
                                signer=self.fqdn,
                                inception=convert_to_epoch_time(inception),
                                expiration=convert_to_epoch_time(expiration),
                                dnskey=ZSK.get_rdata(),
                                verify=False,
                                origin=dns.name.Name(self.fqdn),
                            )
                            rdataset.add(rrsig)

                        except Exception as e:
                            raise e

                self.zone.replace_rdataset(name, rdataset)

    def add_dnskey(self, ttl: int = TTL):
        rdataset = dns.rdataset.Rdataset(
            dns.rdataclass.IN, dns.rdatatype.DNSKEY, ttl=30
        )
        for k in self.domain_class.get_keys():
            rdata = k.get_dnskey_rdata(self.domain_class.get_fqdn())
            rdataset.add(rdata)
        self.zone.replace_rdataset(self.domain_class.get_fqdn(), rdataset)

    def add_ds(
        self,
        sub: Domain,
        digest_algo: DigestAlgorithm = DigestAlgorithm.SHA256,
        ttl=TTL,
    ):
        rdataset = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.DS, ttl=ttl)
        ds_origin = set(
            ["/".join(_k.split("/")[:-1]) for _k in list(self.ds_map.keys())]
        )
        ds_origin.add("CHILD_ERROR")
        for key in sub.get_keys():
            if key.origin_id in ds_origin:
                if key.get_type() == KeyFlags.KSK:
                    ds_record = key.get_ds_record(sub.get_fqdn(), digest_algo, ttl=ttl)
                    rdataset.add(ds_record)

        self.zone.replace_rdataset(sub.get_fqdn(), rdataset)

    def add_nsec_domains(self, ttl=60):
        nsec_candidate = self.domain_class.get_nsec_paramteres(nsec3=False)
        computed_hash = generate_nsec_record(nsec_candidate.keys())

        for c in computed_hash:
            origin = c["original_name"]
            type_for_this_domain = nsec_candidate[origin]
            nsec_rdata = dns.rdata.from_text(
                dns.rdataclass.IN,
                dns.rdatatype.NSEC,
                f"{c["next"]} {' '.join(type_for_this_domain)}",
            )
            rdataset = dns.rdataset.Rdataset(
                dns.rdataclass.IN, dns.rdatatype.NSEC, ttl=ttl
            )

            rdataset.add(nsec_rdata)

            self.zone.replace_rdataset(c["original_name"], rdataset)

    def add_nsec3_domains(
        self,
        iterations: int = 10,
        salt: str = None,
        hash_algo: NSEC3Algo = NSEC3Algo.SHA1,
        flags: int = 0,
        ttl=TTL,
    ):
        if salt is None:
            salt = generate_nsec3_salt()
        nsec_candidate = self.domain_class.get_nsec_paramteres(nsec3=True)
        computed_hash = generate_nsec3_records(
            nsec_candidate.keys(),
            iterations=iterations,
            salt=salt,
            hash_algo=hash_algo,
            flags=flags,
        )

        for c in computed_hash:

            if salt == "":

                nsec3_rdata = dns.rdata.from_text(
                    dns.rdataclass.IN,
                    dns.rdatatype.NSEC3,
                    f'{hash_algo} {flags} {iterations} "-" {c.get("next_hash")} {" ".join(set(nsec_candidate[c["original_name"]]))}',
                )

            else:
                nsec3_rdata = dns.rdata.from_text(
                    dns.rdataclass.IN,
                    dns.rdatatype.NSEC3,
                    f"{hash_algo} {flags} {iterations} {salt} {c.get("next_hash")} {" ".join(set(nsec_candidate[c["original_name"]]))}",
                )

            rdataset = dns.rdataset.Rdataset(
                dns.rdataclass.IN, dns.rdatatype.NSEC3, ttl=ttl
            )
            rdataset.add(nsec3_rdata)
            self.zone.replace_rdataset(f'{c["hash"]}.{self.fqdn}', rdataset)

        if salt == "" or salt == "-":
            nsec3param_rdata = dns.rdata.from_text(
                dns.rdataclass.IN,
                dns.rdatatype.NSEC3PARAM,
                f'{hash_algo} {flags} {iterations} "-"',
            )
        else:
            nsec3param_rdata = dns.rdata.from_text(
                dns.rdataclass.IN,
                dns.rdatatype.NSEC3PARAM,
                f"{hash_algo} {flags} {iterations} {salt}",
            )

        nsec3dataset = dns.rdataset.Rdataset(
            dns.rdataclass.IN, dns.rdatatype.NSEC3PARAM, ttl=ttl
        )
        nsec3dataset.add(nsec3param_rdata)
        self.zone.replace_rdataset(self.domain_class.get_fqdn(), nsec3dataset)

    def add_from_text(self, fqdn, r: RRtypeGen):
        if r is None:
            return

        if r.rrtype is None:
            raise Exception("RRtype is required")

        if r.get_content() is None or len(r.get_content()) == 0:
            return

        self.add_common_content(fqdn, r.rrtype, self.ttl, r.get_content())

    def add_ns(self, fqdn: str, nameservers: list):
        """Add the NameServer (NS) record to the zone file"""
        ns_rdata = dns.rdataset.from_text_list(
            rdataclass.IN, "NS", self.ttl, nameservers
        )
        self.zone.replace_rdataset(fqdn, ns_rdata)

    def add_soa(self, SOA: SOAContent):
        """Add Start of Authority (SOA) record to the zone file."""

        if SOA is None:
            raise Exception("No SOA in the domain to produce zonefile")

        soa_rdata = dns.rdtypes.ANY.SOA.SOA(
            dns.rdataclass.IN,
            dns.rdatatype.SOA,
            mname=SOA.primary_ns,
            rname=SOA.admin_email,
            serial=SOA.serial,
            refresh=SOA.refresh,
            retry=SOA.retry,
            expire=SOA.expire,
            minimum=SOA.expire,
        )

        self.zone.replace_rdataset("@", dns.rrset.from_rdata("@", self.ttl, soa_rdata))

    def add_common_content(self, fqdn, rdtype, ttl, data):
        rdatas = dns.rdataset.from_text_list(rdataclass.IN, rdtype, ttl, data)
        self.zone.replace_rdataset(fqdn, rdatas)

    def zonefile_text(self):
        return self.zone.to_text(
            relativize=False, want_origin=True, sorted=True, want_comments=True
        )

    def to_file(self, path: str, signed: bool = False):
        path_to_save = path + f"db.{self.fqdn.strip('.')}"
        if signed:
            path_to_save += ".signed"

        with open(path_to_save, "w") as f:
            f.write(self.zonefile_text())

    def get_zone(self):
        return self.zone

    def __str__(self):
        """String representation of the generated zone file."""
        return self.zone.to_text(relativize=True, want_origin=True, want_comments=True)
