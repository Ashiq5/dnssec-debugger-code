import base64
import binascii
import random

import dns
from dns.rdatatype import RdataType

from config import *
from crypto.dnssec import (
    DnssecKey,
    DnssecKeyInfo,
    KeyAlgorithm,
    KeyFlags,
    NSEC3Algo,
    dns_sort_key,
    generate_nsec_record,
    generate_nsec3_records,
    nsec3_hash, get_random_algo_not_in_list
)
from domaingenerator import Domain
from domaingenerator import ZonefileGenerator
from utils.logging_utils import logger
from .dnssec_error import (
    DnssecError,
    DnssecErrorType,
)


def revoke_one_key(domain: Domain, key_type: KeyFlags) -> bool:
    """
    Remove one key of the key tags
    Return True on success and False if no key can be revoked
    """
    for k in [
        k for k in domain.get_keys() if k.type == key_type and k.revoked == False
    ]:
        k.revoked = True
        return True

    return False


def remove_all_nsec_rr(children: ZonefileGenerator):
    for name, node in list(children.zone.nodes.items()):
        for rdataset in list(node.rdatasets):  # Go through all rdatasets
            if rdataset.rdtype != dns.rdatatype.NSEC:
                continue  # Skip non-NSEC records

            node.rdatasets.remove(rdataset)  # Remove empty RRSIG set


def modify_last_char_ds(parent: ZonefileGenerator, children: ZonefileGenerator):
    # Modify the hash value of DS
    for name, node in parent.zone.nodes.items():
        if str(name) == children.fqdn:
            rdataset = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.DS)
            if rdataset:
                logger.logger.debug(f"Original DS Record at {name}: {rdataset}")

                # Modify DS record (e.g., corrupting digest or key tag)
                node.delete_rdataset(rdataset.rdclass, dns.rdatatype.DS)
                new_rdataset = node.find_rdataset(
                    rdataset.rdclass, dns.rdatatype.DS, create=True
                )
                for ind, rdata in enumerate(rdataset):
                    if ind == 0:  # Modify only the first DS record found
                        digest_hex = binascii.hexlify(rdata.digest).decode()

                        last_char = digest_hex[-1]
                        while digest_hex[-1] == last_char:
                            digest_hex = digest_hex[:-1] + random.choice(
                                "0123456789abcdef"
                            )

                        modified_ds = dns.rdata.from_text(
                            dns.rdataclass.IN,
                            dns.rdatatype.DS,
                            f"{rdata.key_tag} {rdata.algorithm} {rdata.digest_type} {digest_hex}",
                        )

                        # Replace the DS record
                        new_rdataset.add(modified_ds, ttl=rdataset.ttl)
                    else:
                        digest_hex = binascii.hexlify(rdata.digest).decode()
                        asis_ds = dns.rdata.from_text(
                            dns.rdataclass.IN,
                            dns.rdatatype.DS,
                            f"{rdata.key_tag} {rdata.algorithm} {rdata.digest_type} {digest_hex}",
                        )
                        new_rdataset.add(asis_ds, ttl=rdataset.ttl)
                node.replace_rdataset(new_rdataset)
                logger.logger.debug(f"Modified DS Record at {name}: {new_rdataset}")
                break  # it means we have found DS record to modify, so we can break out of iterating through others


def remove_rrsig_ksk(children: ZonefileGenerator, key_tags: List[int] = list[int]):
    rrsig_to_keep = []
    for name, node in children.zone.nodes.items():
        if str(name) == children.fqdn:
            for r in node:
                if r.rdtype == dns.rdatatype.RRSIG and r.covers == dns.rdatatype.DNSKEY:

                    for dnskey_rrsig in r:
                        if dnskey_rrsig.key_tag in key_tags:
                            logger.logger.debug("Removing RRSIG ", dnskey_rrsig)
                        else:
                            rrsig_to_keep.append(dnskey_rrsig)
                    r.clear()
                    for to_keep in rrsig_to_keep:
                        r.add(to_keep)
                    node.replace_rdataset(r)


def modify_ksk_algo_not_matching_ksk(children_zone: ZonefileGenerator):
    """
    Be carefule, remove all ZSK
    :param children:
    :return:
    """
    new_k_list = []

    for k in children_zone.domain_class.get_keys():
        if k.type == KeyFlags.KSK:
            new_k_list.append(k)

    new_algo = get_random_algo_not_in_list(
        children_zone.domain_class.get_list_ksk_algo()
    )

    new_k = DnssecKeyInfo(DnssecKey.generate(algorithm=new_algo), KeyFlags.ZSK)
    new_k.save(path=X3LD_KEY_DIR, fqdn=children_zone.fqdn)
    new_k_list.append(new_k)

    children_zone.domain_class.keys = new_k_list
    # Generate a new key with the algo


def revoke_bit_dnskey(children: ZonefileGenerator, keyFlags: KeyFlags):
    for name, node in children.zone.nodes.items():
        if str(name) == children.fqdn:
            rdataset = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.DNSKEY)

            if rdataset:

                # Create a new rdataset to store modified records
                new_rdataset = dns.rdataset.Rdataset(
                    dns.rdataclass.IN, dns.rdatatype.DNSKEY
                )
                modification_done = False
                for rdata in rdataset:
                    if (rdata.flags & 0x0001) == 0:  # Ie, a ZSK
                        current_keyf = KeyFlags.ZSK
                    else:
                        current_keyf = KeyFlags.KSK

                    if not modification_done and current_keyf == keyFlags:
                        # Set the Revoke bit (bit 7)
                        logger.logger.debug(f"Original DNSKEY Record at {name}: {rdata}")
                        modification_done = True

                        new_flags = rdata.flags | 0x80
                        modified_rdata = dns.rdtypes.ANY.DNSKEY.DNSKEY(
                            rdataset.rdclass,
                            rdataset.rdtype,
                            new_flags,  # Updated flags
                            rdata.protocol,
                            rdata.algorithm,
                            rdata.key,
                        )
                        logger.logger.debug(f"Modified DNSKEY Record at {name}: {modified_rdata}")

                        new_rdataset.add(modified_rdata, ttl=rdataset.ttl)
                        node.replace_rdataset(new_rdataset)

                    else:
                        new_rdataset.add(rdata, ttl=rdataset.ttl)

                    # Replace the old DNSKEY rdataset with the modified one


#                    break  # Modify only the first DNSKEY record found


def revoke_one_ksk(d: Domain):
    revoke_one_key(d, KeyFlags.KSK)


def revoke_one_zsk(d: Domain):
    revoke_one_key(d, KeyFlags.ZSK)


def change_apex_nsec(zone_children: ZonefileGenerator):
    nsec_values = {}
    for name, node in zone_children.zone.nodes.items():
        rdataset = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.NSEC)
        if rdataset is not None:
            nsec_values[name.__str__()] = rdataset.to_text()

    nsec_dict = generate_nsec_record(list(nsec_values.keys()))
    if len(nsec_dict) <= 1:
        return False
    subdomain_to_modify = nsec_dict[-1]["original_name"]
    current_apex = nsec_dict[-1]["next"]
    new_apex = nsec_dict[1]["original_name"]

    for name, node in zone_children.zone.nodes.items():
        if name.__str__() == subdomain_to_modify:
            rdataset = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.NSEC)
            if rdataset is not None:
                new_rdataset = rdataset[0].__str__().replace(current_apex, new_apex)

                nsec_rdata = dns.rdata.from_text(
                    dns.rdataclass.IN, dns.rdatatype.NSEC, new_rdataset
                )
                rdataset = dns.rdataset.Rdataset(
                    dns.rdataclass.IN, dns.rdatatype.NSEC, ttl=rdataset.ttl
                )

                rdataset.add(nsec_rdata)
                zone_children.zone.replace_rdataset(subdomain_to_modify, rdataset)


def remove_last_nsec_from_a_subdomain(zone_children: ZonefileGenerator):
    salt = ""
    hash_algo = NSEC3Algo.SHA1
    iterations = 0
    flags = 0

    ttl = TTL

    nsec_candidate = zone_children.domain_class.get_nsec_paramteres(nsec3=True)
    names = sorted(nsec_candidate.keys(), key=dns_sort_key)

    computed_hash = generate_nsec3_records(
        names[:-1], iterations=iterations, salt=salt, hash_algo=hash_algo, flags=flags
    )

    logger.logger.debug(nsec_candidate)
    logger.logger.debug(names)
    for i in computed_hash:
        logger.logger.debug(i)

    for c in computed_hash:
        nsec3_rdata = dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.NSEC3,
            f'{hash_algo} {flags} {iterations} "-" {c.get("next_hash")} {" ".join(set(nsec_candidate[c["original_name"]]))}',
        )

        rdataset = dns.rdataset.Rdataset(
            dns.rdataclass.IN, dns.rdatatype.NSEC3, ttl=ttl
        )
        rdataset.add(nsec3_rdata)
        zone_children.zone.replace_rdataset(
            f'{c["hash"]}.{zone_children.fqdn}', rdataset
        )

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
        zone_children.zone.replace_rdataset(
            zone_children.domain_class.get_fqdn(), nsec3dataset
        )


def remove_last_nsec_records(zone_children: ZonefileGenerator):
    for name, node in list(zone_children.zone.nodes.items()):
        for rdataset in list(node.rdatasets):  # Go through all rdatasets
            if rdataset.rdtype != dns.rdatatype.NSEC:
                continue  # Skip non-RRSIG records

            if rdataset.fto_text().split("NSEC ")[1].split(" ")[0] == zone_children.fqdn:
                logger.logger.debug(rdataset.to_text())
                node.rdatasets.remove(rdataset)  # Remove empty RRSIG set


def remove_last_nsec3_records(zone_children: ZonefileGenerator):
    names = []
    for name, node in zone_children.zone.nodes.items():
        if name.__str__() == zone_children.fqdn:
            rdataset = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.NSEC3PARAM)
            if rdataset is None:
                raise Exception("No NSEC3PARAM record found, was expecting one")
            nsec3params = rdataset.to_text().split("NSEC3PARAM ")[1].split(" ")
            itterations = int(nsec3params[2])
            salt = nsec3params[3]
            if salt == "-":
                salt = ""

        if node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.NSEC3) is None:
            names.append(name.__str__())

    nsec3 = generate_nsec3_records(names, iterations=itterations, salt=salt)
    for i in nsec3:
        if i["original_name"] == zone_children.fqdn:
            apex_hash = i["hash"]
            break

    for i in nsec3:
        if i["next_hash"] == apex_hash:
            hash_to_remove = i["hash"]
            break

    zone_children.zone.delete_rdataset(hash_to_remove, rdtype=dns.rdatatype.NSEC3)


def skip_nsec_records(zone_children: ZonefileGenerator, position: int):
    names = [name.__str__() for name, _ in zone_children.zone.nodes.items()]
    nsec_candidate = zone_children.domain_class.get_nsec_paramteres(nsec3=False)

    computed_hash = generate_nsec_record(names)

    computed_hash[position - 1]["next"] = computed_hash[position + 1]["original_name"]
    computed_hash[position]["next"] = computed_hash[position]["original_name"]
    computed_hash = computed_hash[:position] + computed_hash[position + 1 :]

    for c in computed_hash:
        origin = c["original_name"]
        type_for_this_domain = nsec_candidate[origin]
        nsec_rdata = dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.NSEC,
            f"{c["next"]} {' '.join(type_for_this_domain)}",
        )
        rdataset = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.NSEC, ttl=TTL)

        rdataset.add(nsec_rdata)

        zone_children.zone.replace_rdataset(c["original_name"], rdataset)


def skip_nsec3_records(zone_children: ZonefileGenerator, position: int):
    salt = ""
    hash_algo = NSEC3Algo.SHA1
    iterations = 0
    flags = 0
    ttl = 30

    nsec_candidate = zone_children.domain_class.get_nsec_paramteres(nsec3=True)
    names = sorted(nsec_candidate.keys(), key=dns_sort_key)

    computed_hash = generate_nsec3_records(
        names[:position] + names[position + 1 :],
        iterations=iterations,
        salt=salt,
        hash_algo=hash_algo,
        flags=flags,
    )

    for c in computed_hash:
        nsec3_rdata = dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.NSEC3,
            f'{hash_algo} {flags} {iterations} "-" {c.get("next_hash")} {" ".join(set(nsec_candidate[c["original_name"]]))}',
        )

        rdataset = dns.rdataset.Rdataset(
            dns.rdataclass.IN, dns.rdatatype.NSEC3, ttl=ttl
        )
        rdataset.add(nsec3_rdata)
        zone_children.zone.replace_rdataset(
            f'{c["hash"]}.{zone_children.fqdn}', rdataset
        )

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
        zone_children.zone.replace_rdataset(
            zone_children.domain_class.get_fqdn(), nsec3dataset
        )


def remove_one_a_record_and_nsec(zone_children: ZonefileGenerator, also_remove_a=True):
    for name, node in zone_children.zone.nodes.items():
        if name.__str__() == zone_children.fqdn:
            continue

        rdataset_nsec = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.NSEC)
        rdataset_nsec.clear()
        zone_children.zone.replace_rdataset(name, rdataset_nsec)
        if also_remove_a:
            rdataset_a = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.A)
            rdataset_a.clear()
            zone_children.zone.replace_rdataset(name, rdataset_a)
        break


def remove_all_rrsig_ksk(children: ZonefileGenerator, children_use_case: Domain):
    key_tags = children.domain_class.get_list_ksk_tags()
    for name, node in list(children.zone.nodes.items()):
        for rdataset in list(node.rdatasets):  # Go through all rdatasets
            if (
                rdataset.rdtype != dns.rdatatype.RRSIG
                or rdataset.covers == dns.rdatatype.DNSKEY
            ):
                continue  # Skip non-RRSIG records

            new_rdataset = dns.rdataset.Rdataset(rdataset.rdclass, rdataset.rdtype)
            for rdata in rdataset:
                if rdata.key_tag not in key_tags:
                    new_rdataset.add(rdata)  # Keep RRSIGs NOT from ZSKs

            if new_rdataset:
                node.replace_rdataset(new_rdataset)  # Update with filtered RRSIGs
            else:
                node.rdatasets.remove(rdataset)  # Remove empty RRSIG set


def remove_all_dnskey_rrsig_from_ksk(children: ZonefileGenerator):
    key_tags = children.domain_class.get_list_ksk_tags()
    for name, node in list(children.zone.nodes.items()):
        for rdataset in list(node.rdatasets):  # Go through all rdatasets
            if (
                rdataset.rdtype != dns.rdatatype.RRSIG
                or rdataset.covers != dns.rdatatype.DNSKEY
            ):
                continue  # Skip non-RRSIG records

            new_rdataset = dns.rdataset.Rdataset(rdataset.rdclass, rdataset.rdtype)
            for rdata in rdataset:
                if rdata.key_tag not in key_tags:
                    new_rdataset.add(rdata)  # Keep RRSIGs NOT from ZSKs

            if new_rdataset:
                node.replace_rdataset(new_rdataset)  # Update with filtered RRSIGs
            else:
                node.rdatasets.remove(rdataset)  # Remove empty RRSIG set


def remove_all_subdomains_rrsig(children: ZonefileGenerator):
    for name, node in list(children.zone.nodes.items()):
        if name.__str__() == children.fqdn:
            continue

        for rdataset in list(node.rdatasets):  # Go through all rdatasets
            if rdataset.rdtype != dns.rdatatype.RRSIG:
                continue  # Skip non-RRSIG records

            node.rdatasets.remove(rdataset)  # Remove empty RRSIG set


def remove_all_rrsig_zsk(children: ZonefileGenerator):
    key_tags = children.domain_class.get_list_zsk_tags()
    for name, node in list(children.zone.nodes.items()):
        for rdataset in list(node.rdatasets):  # Go through all rdatasets
            if rdataset.rdtype != dns.rdatatype.RRSIG:
                continue  # Skip non-RRSIG records

            new_rdataset = dns.rdataset.Rdataset(rdataset.rdclass, rdataset.rdtype)
            for rdata in rdataset:
                if rdata.key_tag not in key_tags:
                    new_rdataset.add(rdata)  # Keep RRSIGs NOT from ZSKs

            if new_rdataset:
                node.replace_rdataset(new_rdataset)  # Update with filtered RRSIGs
            else:
                node.rdatasets.remove(rdataset)  # Remove empty RRSIG set


def modify_all_rrsigs(zone_children: ZonefileGenerator):
    """Modifies all signatures in the DNS zone."""
    for name, node in zone_children.zone.nodes.items():
        for rdataset in node.rdatasets:
            if rdataset.rdtype == dns.rdatatype.RRSIG:
                new_rdataset = dns.rdataset.Rdataset(rdataset.rdclass, rdataset.rdtype)

                for rdata in rdataset:
                    # Generate a random signature of the same length
                    modified_sig = os.urandom(len(rdata.signature))

                    # Create a modified RRSIG record
                    modified_rrsig = dns.rdtypes.ANY.RRSIG.RRSIG(
                        rdataset.rdclass,
                        rdataset.rdtype,
                        rdata.type_covered,
                        rdata.algorithm,
                        rdata.labels,
                        rdata.original_ttl,
                        rdata.expiration,
                        rdata.inception,
                        rdata.key_tag,
                        rdata.signer,
                        modified_sig,
                    )

                    logger.logger.debug("Original RRSIG: ", rdata.signature, rdata.key_tag)
                    logger.logger.debug("Modified RRSIG: ", modified_sig)
                    new_rdataset.add(modified_rrsig, ttl=rdataset.ttl)

                node.replace_rdataset(new_rdataset)


def remove_one_zsk_from_the_children(children: Domain):
    ksks = []
    zsks = []
    for k in children.get_keys():
        if k.type == KeyFlags.KSK:
            ksks.append(k)
        elif k.type == KeyFlags.ZSK:
            zsks.append(k)
        else:
            raise Exception("Unknown key type")

    zsks.pop()
    children.keys = zsks + ksks


def remove_a_zsk_from_the_children_for_secondary_server(children: ZonefileGenerator):
    for name, node in list(children.zone.nodes.items()):
        for rdataset in list(node.rdatasets):  # Go through all rdatasets
            if rdataset.rdtype != dns.rdatatype.DNSKEY:
                continue  # Skip non-RRSIG records

            new_rdataset = dns.rdataset.Rdataset(rdataset.rdclass, rdataset.rdtype)
            is_first_zsk_removed = False
            for ind, rdata in enumerate(rdataset):
                """if int(rdata.flags) != 256:
                new_rdataset.add(rdata, ttl=TTL)
                continue"""
                if is_first_zsk_removed:
                    new_rdataset.add(rdata, ttl=TTL)
                else:
                    is_first_zsk_removed = True

            if new_rdataset:
                node.replace_rdataset(new_rdataset)
            else:
                node.rdatasets.remove(rdataset)


def remove_one_ksk_from_the_children(children: Domain):
    ksks = []
    zsks = []
    for k in children.get_keys():
        if k.type == KeyFlags.KSK:
            ksks.append(k)
        elif k.type == KeyFlags.ZSK:
            zsks.append(k)
        else:
            raise Exception("Unknown key type")

    ksks.pop()
    children.keys = zsks + ksks


def add_a_ds_to_the_parent_zone(children_fqdn: str, zone_parent: ZonefileGenerator):
    digest_hex = ""
    for _ in range(0, 64):
        digest_hex = digest_hex + random.choice("0123456789abcdef")
    dummy_ds = dns.rdata.from_text(
        dns.rdataclass.IN,
        dns.rdatatype.DS,
        f"{random.randrange(11111,55555)} {16} {2} {digest_hex}",
    )
    for name, node in zone_parent.zone.nodes.items():
        if str(name) == children_fqdn:
            new_rdataset = node.find_rdataset(
                dns.rdataclass.IN, dns.rdatatype.DS, create=True
            )
            new_rdataset.add(dummy_ds, ttl=TTL)

            logger.logger.debug(f"Added a new dummy DS record {children_fqdn}: {new_rdataset}")


def remove_a_record_from_subdomain_a(children: Domain):
    for sub in children.get_subdomains():
        if sub.fqdn == "a." + children.fqdn:
            sub.A = None
            break


def remove_record_type_for_a_subdomain(
    zone_children: ZonefileGenerator, rdtype: RdataType, subdomain=""
):
    for name, node in zone_children.zone.nodes.items():
        if name.__str__() == f"{subdomain}." + zone_children.fqdn:
            rdataset = node.get_rdataset(dns.rdataclass.IN, rdtype)
            if rdataset:
                rdataset.clear()
                zone_children.zone.replace_rdataset(name, rdataset)
            break


def remove_nsec(zone_children: ZonefileGenerator):
    for name, node in zone_children.zone.nodes.items():
        rdataset_nsec = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.NSEC)
        if rdataset_nsec:
            rdataset_nsec.clear()

        rdataset_nsec = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.NSEC3)
        if rdataset_nsec:
            rdataset_nsec.clear()
        # zone_children.zone.replace_rdataset(name, rdataset_nsec)


def remove_nsec_from_a_subdomain(zone_children: ZonefileGenerator, subdomain=""):
    for name, node in zone_children.zone.nodes.items():
        if name.__str__() == f"{subdomain}." + zone_children.fqdn:
            rdataset_nsec = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.NSEC)
            rdataset_nsec.clear()
            zone_children.zone.replace_rdataset(name, rdataset_nsec)
            # should remove nsec here
            break


# Ishtiaq's part
def get_nsec_parameters_from_zone(zone_children):
    for name, node in zone_children.zone.nodes.items():
        if name.__str__() == zone_children.fqdn:
            rdataset = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.NSEC3PARAM)
            if rdataset is None:
                return "NSEC", None
            nsec3params = rdataset.to_text().split("NSEC3PARAM ")[1].split(" ")
            flags = int(nsec3params[0])
            iterations = int(nsec3params[2])
            salt = nsec3params[3]
            if salt == "-":
                salt = ""
            return "NSEC3", (NSEC3Algo.SHA1, flags, iterations, salt)
    raise Exception("Should not reach here")


def modify_last_bit_of_nsec3_hash(children: ZonefileGenerator):
    # Modify the hash value of DS
    for name, node in children.zone.nodes.items():
        if len(str(name)) > len(children.fqdn):  # pick any subdomain
            rdataset = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.NSEC3)
            if rdataset:  # check whether it has NSEC3 record
                logger.logger.debug(f"Original NSEC3 Record at {name}: {rdataset}")

                # Modify NSEC3 record (e.g., corrupting digest or key tag)
                for rdata in rdataset:
                    next_owner_name_hash = binascii.hexlify(rdata.next).decode()

                    last_char = next_owner_name_hash[-1]
                    while next_owner_name_hash[-1] == last_char:
                        next_owner_name_hash = next_owner_name_hash[
                            :-1
                        ] + random.choice("0123456789abcdef")
                    next_owner_name_hash = base64.b32encode(
                        binascii.unhexlify(next_owner_name_hash)
                    ).decode()
                    modified_nsec3 = dns.rdata.from_text(
                        dns.rdataclass.IN,
                        dns.rdatatype.NSEC3,
                        f"{rdata.algorithm} {rdata.flags} {rdata.iterations} {binascii.hexlify(rdata.salt).decode()} {next_owner_name_hash} {dns.rdtypes.ANY.NSEC3.Bitmap(rdata.windows).to_text()}",
                    )

                    # Replace the NSEC3 record
                    rdataset.clear()
                    rdataset.add(modified_nsec3)

                logger.logger.debug(f"Modified NSEC3 Record at {name}: {rdataset}")
                return name


def compute_key_tag(
    flags: int, protocol: int, algorithm: int, public_key: bytes
) -> int:
    """
    Compute the key tag (RFC 4034 Appendix B).
    Also used by dnssec-dsfromkey and other DNS tools.
    """
    # Construct DNSKEY RDATA (without length bytes, just the content):
    rdata = bytearray()
    # 2 bytes flags
    rdata.append((flags >> 8) & 0xFF)
    rdata.append(flags & 0xFF)
    # 1 byte protocol
    rdata.append(protocol & 0xFF)
    # 1 byte algorithm
    rdata.append(algorithm & 0xFF)
    # public key bytes
    rdata.extend(public_key)

    # Now apply the key-tag algorithm:
    # "The key Tag is the same as what BIND generates for a DNSKEY"
    acc = 0
    for i, v in enumerate(rdata):
        acc += v << 8 if i & 1 == 0 else v
    acc = (acc & 0xFFFF) + (acc >> 16)
    return acc & 0xFFFF


def replace_rdata_and_rrsig(
    children_zone: ZonefileGenerator,
    owner_name: str = None,
    type: dns.rdatatype.RdataType = dns.rdatatype.NONE,
    ttl: int = None,
    rrsig_ttl: int = None,
    expiration: str = DEFAULT_EXPIRATION,
    new_rdata: dns.rdata.Rdata = None,
    signer: str = None,
    labels: int = None,
    is_original_ttl_exceeded_rrsig: bool = False,
):
    keys = children_zone.domain_class.get_keys()
    zsks = [k for k in keys if k.type == KeyFlags.ZSK]
    ksks = [k for k in keys if k.type == KeyFlags.KSK]
    if len(zsks) == 0:
        zsks = ksks
    for name, node in children_zone.zone.nodes.items():
        if str(name) == owner_name:
            rdataset = node.get_rdataset(dns.rdataclass.IN, type)
            if rdataset:
                if ttl:
                    node.delete_rdataset(rdataset.rdclass, type)  # delete this A rrset
                    new_rdataset = node.find_rdataset(
                        rdataset.rdclass, type, create=True
                    )
                    for rdata in rdataset:  # change the TTL of this rdataset
                        new_rdataset.add(rdata, ttl=ttl)
                    node.replace_rdataset(new_rdataset)  # replace with new TTL
                    rdataset = new_rdataset
                if new_rdata:
                    node.delete_rdataset(rdataset.rdclass, type)  # delete this A rrset
                    new_rdataset = node.find_rdataset(
                        rdataset.rdclass, type, create=True
                    )
                    new_rdataset.add(new_rdata, ttl=rdataset.ttl)
                    node.replace_rdataset(new_rdataset)  # replace with new rdata
                    rdataset = new_rdataset
                rdatas = [rdata for rdata in rdataset]
                if ttl:
                    rrset = dns.rrset.from_rdata_list(name, ttl, rdatas)
                else:
                    rrset = dns.rrset.from_rdata_list(name, rdataset.ttl, rdatas)
                node.delete_rdataset(
                    rdataset.rdclass, dns.rdatatype.RRSIG, type
                )  # delete rrsigset covering A rrset
                inception = DEFAULT_INCEPTION
                expiration = expiration
                if signer:
                    signer_name = signer
                else:
                    signer_name = children_zone.fqdn
                for zsk_meta in zsks:
                    rrsig = dns.dnssec.sign(
                        rrset=rrset,
                        private_key=zsk_meta.get_key().get_private_key_bit(),
                        signer=signer_name,
                        inception=inception,
                        expiration=expiration,
                        dnskey=zsk_meta.get_rdata(),
                        rrsig_ttl=(
                            rrsig_ttl if not is_original_ttl_exceeded_rrsig else ttl
                        ),
                        verify=True,
                        labels=labels,
                    )
                    rrsig_rdata = dns.rdata.from_text(
                        rrset.rdclass, dns.rdatatype.RRSIG, rrsig.to_text()
                    )
                    # Add the new RRSIG rdataset explicitly
                    rrsig_rdataset = node.find_rdataset(
                        rrset.rdclass, dns.rdatatype.RRSIG, covers=type, create=True
                    )
                    if rrsig_ttl:
                        rrsig_rdataset.add(rrsig_rdata, ttl=rrsig_ttl)
                    else:
                        rrsig_rdataset.add(rrsig_rdata, ttl=rdataset.ttl)
                    node.replace_rdataset(rrsig_rdataset)
                break


def get_types_present(node, mandatory_types, error_list, which):
    types_present = (
        set([rdataset.rdtype for rdataset in node.rdatasets]) | mandatory_types
    )
    if which == "referral":
        if DnssecErrorType.REFERRAL_WITHOUT_NS in error_list:
            # Removed NS record from the bitmap of a delegated name to induce this error
            types_present.remove(dns.rdatatype.RdataType.NS)
        if DnssecErrorType.REFERRAL_WITH_DS in error_list:
            # Added DS record to the bitmap of an unsigned delegation to induce this error
            types_present.add(dns.rdatatype.RdataType.DS)
        if DnssecErrorType.REFERRAL_WITH_SOA in error_list:
            # Added SOA record to the bitmap of an unsigned delegation to induce this error
            types_present.add(dns.rdatatype.RdataType.SOA)
    else:
        if DnssecErrorType.STYPE_IN_BITMAP in error_list:
            # Added an absent record to the bitmap to induce this error
            types_present.add(dns.rdatatype.RdataType.MX)
        if DnssecErrorType.EXISTING_TYPE_NOT_IN_BITMAP in error_list:
            # Removed an existing record type from the bitmap to induce this error
            # types_present.pop()
            types_present.remove(dns.rdatatype.RdataType.A)
    return types_present


def manipulate_nsec_bitmap(
    owner_name: str,
    zone_to_change: ZonefileGenerator,
    error_list: List[DnssecError],
    which: str = None,
):
    if not which:
        raise Exception("No error type specified.")
    # RR types explicitly defined
    mandatory_types = {dns.rdatatype.RdataType.RRSIG, dns.rdatatype.RdataType.NSEC}
    for name, node in zone_to_change.zone.nodes.items():
        if str(name) == owner_name:
            logger.logger.debug(
                "Original Type bitmap for " + owner_name + " is ",
                set([rdataset.rdtype for rdataset in node.rdatasets]),
            )
            types_present = get_types_present(node, mandatory_types, error_list, which)
            logger.logger.debug("Modified Type bitmap for " + owner_name + " is ", types_present)
            rdataset = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.NSEC)
            if rdataset:
                for rdata in rdataset:
                    windows = dns.rdtypes.ANY.NSEC.Bitmap.from_rdtypes(types_present)
                    # Create NSEC RDATA explicitly
                    nsec_rdata = dns.rdtypes.ANY.NSEC.NSEC(
                        rdclass=dns.rdataclass.IN,
                        rdtype=dns.rdatatype.RdataType.NSEC,
                        next=rdata.next,
                        windows=windows,
                    )
                    replace_rdata_and_rrsig(
                        zone_to_change,
                        owner_name=owner_name,
                        type=dns.rdatatype.NSEC,
                        new_rdata=nsec_rdata,
                    )
                    logger.logger.debug("Replaced rdata and RRSIG of " + owner_name)
                    return


def manipulate_nsec3_bitmap(
    owner_name: str,
    zone_to_change: ZonefileGenerator,
    error_list: List[DnssecError],
    nsec_params: tuple = None,
    which: str = None,
):
    if not which:
        raise Exception("No error type specified.")
    if not nsec_params:
        raise Exception("No NSEC3 parameters specified.")
    # RR types explicitly defined
    mandatory_types = {dns.rdatatype.RdataType.RRSIG}
    hashed_name = (
        nsec3_hash(owner_name, nsec_params[3], nsec_params[2], nsec_params[0])
        + "."
        + zone_to_change.fqdn
    )
    for name, node in zone_to_change.zone.nodes.items():
        if str(name) == owner_name:
            logger.logger.debug(
                "Original Type bitmap for " + owner_name + " is ",
                set([rdataset.rdtype for rdataset in node.rdatasets]),
            )
            types_present = get_types_present(node, mandatory_types, error_list, which)
            logger.logger.debug("Modified Type bitmap for " + owner_name + " is ", types_present)
            for hname, hnode in zone_to_change.zone.nodes.items():
                if str(hname) == hashed_name:
                    rdataset = hnode.get_rdataset(
                        dns.rdataclass.IN, dns.rdatatype.NSEC3
                    )
                    if rdataset:
                        for rdata in rdataset:
                            windows = dns.rdtypes.ANY.NSEC3.Bitmap.from_rdtypes(
                                types_present
                            )
                            # Create NSEC3 RDATA explicitly
                            nsec3_rdata = dns.rdtypes.ANY.NSEC3.NSEC3(
                                rdclass=dns.rdataclass.IN,
                                rdtype=dns.rdatatype.RdataType.NSEC3,
                                algorithm=rdata.algorithm,
                                flags=rdata.flags,
                                iterations=rdata.iterations,
                                salt=rdata.salt,
                                next=rdata.next,
                                windows=windows,
                            )
                            replace_rdata_and_rrsig(
                                zone_to_change,
                                owner_name=hashed_name,
                                type=dns.rdatatype.NSEC3,
                                new_rdata=nsec3_rdata,
                            )
                            logger.logger.debug("Replaced rdata and RRSIG of " + hashed_name)
                            return


def change_nsec_next(zone_children: ZonefileGenerator):
    owner_name = zone_children.fqdn
    next_name = dns.name.from_text(zone_children.fqdn)
    # RR types explicitly defined
    mandatory_types = {dns.rdatatype.RdataType.RRSIG, dns.rdatatype.RdataType.NSEC}
    for name, node in zone_children.zone.nodes.items():
        if str(name) == owner_name:
            types_present = (
                set([rdataset.rdtype for rdataset in node.rdatasets]) | mandatory_types
            )
            windows = dns.rdtypes.ANY.NSEC.Bitmap.from_rdtypes(types_present)
            # Create NSEC RDATA explicitly
            nsec_rdata = dns.rdtypes.ANY.NSEC.NSEC(
                rdclass=dns.rdataclass.IN,
                rdtype=dns.rdatatype.RdataType.NSEC,
                next=next_name,
                windows=windows,
            )
            replace_rdata_and_rrsig(
                zone_children,
                owner_name=zone_children.fqdn,
                type=dns.rdatatype.NSEC,
                new_rdata=nsec_rdata,
            )
            break


def change_nsec3_next(zone_children: ZonefileGenerator, nsec_params):
    if not nsec_params:
        raise Exception("No NSEC3 parameters specified.")
    owner_name = zone_children.fqdn
    nsec3hash = nsec3_hash(owner_name, nsec_params[3], nsec_params[2], nsec_params[0])
    hashed_name = nsec3hash + "." + owner_name
    next_name = base64.b32hexdecode(nsec3hash)
    # RR types explicitly defined
    mandatory_types = {dns.rdatatype.RdataType.RRSIG}
    for name, node in zone_children.zone.nodes.items():
        if str(name) == owner_name:
            types_present = (
                set([rdataset.rdtype for rdataset in node.rdatasets]) | mandatory_types
            )
            for hname, hnode in zone_children.zone.nodes.items():
                if str(hname) == hashed_name:
                    rdataset = hnode.get_rdataset(
                        dns.rdataclass.IN, dns.rdatatype.NSEC3
                    )
                    if rdataset:
                        for rdata in rdataset:
                            # Create NSEC3 RDATA explicitly
                            windows = dns.rdtypes.ANY.NSEC3.Bitmap.from_rdtypes(
                                types_present
                            )
                            nsec3_rdata = dns.rdtypes.ANY.NSEC3.NSEC3(
                                rdclass=dns.rdataclass.IN,
                                rdtype=dns.rdatatype.RdataType.NSEC3,
                                algorithm=rdata.algorithm,
                                flags=rdata.flags,
                                iterations=rdata.iterations,
                                salt=rdata.salt,
                                next=next_name,
                                windows=windows,
                            )
                            replace_rdata_and_rrsig(
                                zone_children,
                                owner_name=hashed_name,
                                type=dns.rdatatype.NSEC3,
                                new_rdata=nsec3_rdata,
                            )
                            return


def save_zonefile_for_secondary_ns(
    zone_parent: ZonefileGenerator, zone_children: ZonefileGenerator
):
    zone_parent.to_file(ZONE_DIR_SECOND_NS, signed=True)
    zone_children.to_file(ZONE_DIR_SECOND_NS, signed=True)


def remove_nsec_for_a_specific_subdomain(zone_children: ZonefileGenerator, subdomain):
    for name, node in list(zone_children.zone.nodes.items()):
        if name[0] != subdomain:
            continue
        for rdataset in list(node.rdatasets):  # Go through all rdatasets
            if rdataset.rdtype != dns.rdatatype.NSEC:
                continue  # Skip non-RRSIG records
            node.rdatasets.remove(rdataset)  # Re


def remove_rrsig_for_an_algo(zone_children: ZonefileGenerator, algo_list):
    if len(algo_list) == 0:
        return
    algo_to_remove = random.choice(algo_list)
    logger.logger.debug(f"Removing RRSIG for ZSK algo {algo_to_remove}")

    for name, node in list(zone_children.zone.nodes.items()):
        for rdataset in list(node.rdatasets):  # Go through all rdatasets
            if (
                rdataset.rdtype != dns.rdatatype.RRSIG
                or rdataset.covers == dns.rdatatype.DNSKEY
            ):
                continue  # Skip non-RRSIG records

            new_rdataset = dns.rdataset.Rdataset(rdataset.rdclass, rdataset.rdtype)
            for rdata in rdataset:
                if rdata.algorithm != algo_to_remove:
                    new_rdataset.add(rdata)  # Keep RRSIGs NOT from ZSKs

            if new_rdataset:
                node.replace_rdataset(new_rdataset)  # Update with filtered RRSIGs
            else:
                node.rdatasets.remove(rdataset)  # Remove empty RRSIG set


def add_a_zsk_to_children(children: Domain, key_type: KeyFlags, alg: KeyAlgorithm):
    children.add_key(DnssecKeyInfo(DnssecKey.generate(algorithm=alg), type=key_type))
