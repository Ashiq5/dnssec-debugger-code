import random
from enum import IntEnum
from typing import List

from faker import Faker

from crypto import DnssecKeyInfo, KeyFlags
from .rrtype_gen import (
    AAAAContent,
    AContent,
    EMPTYContent,
    NSContent,
    SOAContent,
    TXTContent,
)


class DomainInstruction(IntEnum):
    ADD_SUBDOMAIN = 1
    REMOVE_A_RECORD = 2


class DomainSpecificParameters:
    def __init__(self, domain_instruction: DomainInstruction, options=None):
        if options is None:
            options = dict()

        self.options = options
        self.domain_instruction = domain_instruction


class Domain:
    def __init__(self, fqdn: str, parent: bool = False):

        self.fqdn = fqdn

        # If settings new RRtypen don't fortget to add it to the RRtypeList(self) function
        self.A = None
        self.AAAA = None
        self.TXT = None
        self.NS = None
        self.SOA = None
        self.DS = None
        self.DNSKEY = None
        self.keys: list[DnssecKeyInfo] = []

        self.subdomains = []

    # todo import Domain from zonefile ?
    @classmethod
    def from_zonefile(cls, path):
        instance = cls("test")
        return instance

    @classmethod
    def generate(
        cls,
        domain,
        nb_subdomain,
        additional_record: bool = True,
        wildcard_subdomain: bool = False,
        specific_parameters: List[DomainSpecificParameters] = None,
    ):
        if domain[-1] != ".":
            raise Exception("Domain must end with '.'")
        instance = cls(domain)

        if additional_record:
            instance.A = AContent()
            instance.AAAA = AAAAContent()
            instance.TXT = TXTContent()
        instance.NS = NSContent()

        subdomains_candidate = []
        for i in range(nb_subdomain):
            while True:
                if i == 0:
                    sub_fqdn = "a"
                elif i == 1:
                    sub_fqdn = "d"
                elif i == 2:
                    sub_fqdn = "m"
                elif i == 3:
                    sub_fqdn = "z"
                else:
                    sub_fqdn = "".join(Faker().random_letters(random.randint(3, 10)))
                if sub_fqdn not in instance.subdomains:
                    subdomains_candidate.append(sub_fqdn)
                    break
            if wildcard_subdomain:
                subdomains_candidate.append("*")
        for s in subdomains_candidate:
            instance.subdomains.append(
                Domain.generate(f"{s.lower()}.{domain}", nb_subdomain=0)
            )
        if specific_parameters is None:
            specific_parameters = []

        for parameter in specific_parameters:

            # Specific Subdomains options
            if parameter.domain_instruction == DomainInstruction.ADD_SUBDOMAIN:
                # First remove the domain name if on the list.
                subdomain_str = parameter.options.get("subdomain", "")
                for s in instance.subdomains:
                    if s.fqdn == f"{subdomain_str}.{domain}":
                        instance.subdomains.remove(s)
                        break

                instance.subdomains.append(
                    Domain.generate(
                        domain=f"{subdomain_str}.{domain}",
                        nb_subdomain=parameter.options.get("nb_subdomains", 1),
                        additional_record=parameter.options.get(
                            "additional_records", True
                        ),
                        wildcard_subdomain=parameter.options.get(
                            "wildcard_subdomain", False
                        ),
                    )
                )

            elif parameter.domain_instruction == DomainInstruction.REMOVE_A_RECORD:
                subdomain_to_modify = parameter.options.get("subdomain", None)
                if subdomain_to_modify is None:
                    continue

                if subdomain_to_modify == "":
                    instance.A = None
                else:
                    for sub in instance.subdomains:
                        if sub.fqdn == f"{subdomain_to_modify}.{domain}":
                            sub.A = None
                            break

        return instance

    def add_key(self, key: DnssecKeyInfo):
        if self.DNSKEY is None:
            self.DNSKEY = EMPTYContent(
                rrtype="DNSKEY",
                description=f"DNSKEY type {key.get_type()}, revoked : {key.get_revoked()}",
            )
            self.DS = EMPTYContent(
                rrtype="DS",
                description=f"DS type {key.get_type()}, domain : {self.get_fqdn()}",
            )
        self.keys.append(key)

    def get_keys(self) -> List[DnssecKeyInfo]:
        return self.keys

    def RRtypeList(self):
        rrList = [
            rr
            for rr in [self.SOA, self.A, self.AAAA, self.TXT, self.DNSKEY]
            if rr is not None
        ]
        if self.is_delegated() and self.NS is not None:
            rrList = rrList + [rr for rr in [self.NS, self.DS] if rr is not None]
        return rrList

    def get_nsec_paramteres(self, nsec3: bool = False):
        res = dict()
        if nsec3:
            mandatory_types = ["RRSIG"]
        else:
            mandatory_types = ["RRSIG", "NSEC"]
        res[self.fqdn] = [
            rrData.rrtype for rrData in self.RRtypeList() if rrData.rrtype not in ["DS"]
        ] + mandatory_types
        if nsec3:
            res[self.fqdn] = res[self.fqdn] + ["NSEC3PARAM"]

        for subdomain in self.subdomains:
            if subdomain.is_delegated():
                if res.get(subdomain.fqdn) is None:
                    res[subdomain.fqdn] = []
                # TODO: not working as it should, but unintentionally does good, read handle_error REFERRAL_WITH_SOA for more
                if subdomain.is_delegated_and_signed():
                    res[subdomain.fqdn] = res[subdomain.fqdn] + [
                        rr.rrtype for rr in [self.DS, self.NS] if rr is not None
                    ]
                else:
                    res[subdomain.fqdn] = res[subdomain.fqdn] + [
                        rr.rrtype for rr in [self.NS] if rr is not None
                    ]
            else:
                res = res | subdomain.get_nsec_paramteres()

        return res

    def get_list_keys_algo(self):
        return {
            "ksk": list(
                set(
                    [
                        k.get_key().algorithm
                        for k in self.get_keys()
                        if k.type == KeyFlags.KSK
                    ]
                )
            ),
            "zsk": list(
                set(
                    [
                        k.get_key().algorithm
                        for k in self.get_keys()
                        if k.type == KeyFlags.ZSK
                    ]
                )
            ),
        }

    def get_list_ksk_algo(self):
        return self.get_list_keys_algo()["ksk"]

    def get_list_keys_tags(self):
        return {
            "ksk": list(
                set([k.key_tag for k in self.get_keys() if k.type == KeyFlags.KSK])
            ),
            "zsk": list(
                set([k.key_tag for k in self.get_keys() if k.type == KeyFlags.ZSK])
            ),
        }

    def get_list_ksk_tags(self):
        return self.get_list_keys_tags()["ksk"]

    def get_list_zsk_tags(self):
        return self.get_list_keys_tags()["zsk"]

    def get_list_zsk_algo(self):
        return self.get_list_keys_tags()["zsk"]

    def is_delegated(self):
        return not (self.SOA is None or self.NS is None)

    def is_delegated_and_signed(self):
        return self.is_delegated() and self.DS is not None

    def __str__(self):
        """String representation of the domain and its records."""
        res = "".join(f"{self.fqdn} {_}\n" for _ in self.RRtypeList())
        for s in self.subdomains:
            res += str(s)
        return res

    def to_dict(self):  # todo add SOA
        """Convert domain and subdomains to a dictionary format."""
        res = {self.fqdn: []}
        for r in self.RRtypeList():
            res[self.fqdn].append({"content": r.get_content(), "type": r.rrtype})

        for sub in self.subdomains:
            res |= sub.to_dict()

        return res

    def set_subdomains(self, subdomains: list):
        """Set subdomains for the domain."""
        self.subdomains = subdomains

    def get_fqdn(self):
        """Return the domain name."""
        return self.fqdn

    def get_subdomains(self):
        return self.subdomains

    def add_subdomain(self, subdomains):
        self.subdomains.append(subdomains)

    def set_ns(self, nameservers: List[str]):
        if nameservers is None:
            raise Exception("set nameservers cannot be None")

        self.NS = NSContent(nameservers)

    def set_soa(self, SOA: SOAContent):
        self.SOA = SOA
