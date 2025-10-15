import datetime
import glob

import dns

from config import *
from crypto import (
    KeysOption,
    KeysOptions,
    NsecOption,
    NsecVersion,
    DnssecKey,
    DnssecKeyInfo,
    KeyAlgorithm,
    KeyFlags,
)
from domaingenerator import SOAContent, AContent, DomainSpecificParameters, Domain
from domaingenerator import SigningParameters, ZonefileGenerator
from utils import get_errcodes
from utils.logging_utils import logger
from .dnssec_error import DnssecPriority, DnssecError, DnssecErrorType, DnssecErrors
from .error_handler import (
    get_nsec_parameters_from_zone,
    modify_last_char_ds,
    modify_all_rrsigs,
    remove_one_ksk_from_the_children,
    remove_rrsig_ksk,
    change_apex_nsec,
    remove_record_type_for_a_subdomain,
    remove_nsec,
    remove_all_nsec_rr,
    remove_last_nsec3_records,
    remove_nsec_for_a_specific_subdomain,
    remove_all_subdomains_rrsig,
    remove_all_rrsig_ksk,
    revoke_one_ksk,
    revoke_one_zsk,
    add_a_ds_to_the_parent_zone,
    remove_rrsig_for_an_algo,
    remove_all_rrsig_zsk,
    add_a_zsk_to_children,
    replace_rdata_and_rrsig,
    change_nsec_next,
    change_nsec3_next,
    modify_last_bit_of_nsec3_hash,
    manipulate_nsec_bitmap,
    manipulate_nsec3_bitmap,
)


# from .error_handler import


def prepare_root():
    # Prepare domain for root domain
    root_domain_name = DOMAIN
    root_domain_class = Domain.generate(root_domain_name, nb_subdomain=1)
    root_domain_class.set_ns(ROOT_NS)
    root_domain_class.set_soa(SOAContent(root_domain_name))

    # one-time
    # ksk_root = DnssecKeyInfo(DnssecKey.generate(algorithm=13), KeyFlags.KSK)
    # zsk_root = DnssecKeyInfo(DnssecKey.generate(algorithm=13), KeyFlags.ZSK)
    # zsk_root.save(path=BASE_KEY_DIR, fqdn=root_domain_name)
    # ksk_root.save(path=BASE_KEY_DIR, fqdn=root_domain_name)

    # Instead we are going to load the key
    # Load root keys
    # DOCKER
    ksk_root = DnssecKeyInfo.from_file(
        BASE_KEY_DIR, fqdn=root_domain_name, algo=8, key_tag=16969
    )

    zsk_root = DnssecKeyInfo.from_file(
        BASE_KEY_DIR, fqdn=root_domain_name, algo=8, key_tag=46948
    )

    # Add the keys to root
    root_domain_class.add_key(zsk_root)
    root_domain_class.add_key(ksk_root)

    ns1_sub = Domain.generate(
        "ns1." + root_domain_class.get_fqdn(),
        additional_record=False,
        nb_subdomain=0,
    )
    ns1_sub.A = AContent()
    ns1_sub.A.content = [IP_1]
    ns2_sub = Domain.generate(
        "ns2." + root_domain_class.get_fqdn(),
        additional_record=False,
        nb_subdomain=0,
    )
    ns2_sub.A = AContent()
    ns2_sub.A.content = [IP_2]
    ns3_sub = Domain.generate(
        "ns3." + root_domain_class.get_fqdn(),
        additional_record=False,
        nb_subdomain=0,
    )
    ns3_sub.A = AContent()
    ns3_sub.A.content = [IP_1]
    ns4_sub = Domain.generate(
        "ns4." + root_domain_class.get_fqdn(),
        additional_record=False,
        nb_subdomain=0,
    )
    ns4_sub.A = AContent()
    ns4_sub.A.content = [IP_2]

    root_domain_class.add_subdomain(ns1_sub)
    root_domain_class.add_subdomain(ns2_sub)
    root_domain_class.add_subdomain(ns3_sub)
    root_domain_class.add_subdomain(ns4_sub)
    # Generate the ZoneFiles
    root_zone_file = ZonefileGenerator(
        root_domain_class, ttl=TTL, nameservers=root_domain_class.NS.get_nameservers()
    )

    # Save the unsigned zonefile
    root_zone_file.to_file(ZONE_DIR, signed=False)
    if HAVE_SECONDARY_ZONE:
        root_zone_file.to_file(ZONE_DIR_SECOND_NS, signed=False)

    # Now proceed to NSEC3 opperations
    root_zone_file.add_nsec3_domains(salt=DEFAULT_SALT, iterations=0)

    # And sign
    # By the way, all the zonefile operations are independent, no need to get test1 zonefile ...
    root_zone_file.sign()

    # Save the zone file, signed
    root_zone_file.to_file(ZONE_DIR, signed=True)
    if HAVE_SECONDARY_ZONE:
        root_zone_file.to_file(ZONE_DIR_SECOND_NS, signed=True)

    # You are good to upload everything that is in automated folder
    return root_domain_class, root_zone_file


def delete_old_keys():
    # Loop over all files and delete them one by one
    for directory in os.listdir(X3LD_KEY_DIR):
        for file in glob.glob(X3LD_KEY_DIR + directory + "/*"):
            os.remove(file)
            logger.logger.debug("Deleted " + str(file))


def update_root(root_zone_file: ZonefileGenerator, subdomain: Domain):
    root_zone_file.add_ds(subdomain)
    root_zone_file.add_ns(subdomain.fqdn, nameservers=PARENT_NS)

    # Save the unsigned zonefile
    root_zone_file.to_file(ZONE_DIR, signed=False)
    if HAVE_SECONDARY_ZONE:
        root_zone_file.to_file(ZONE_DIR_SECOND_NS, signed=False)

    # Now proceed to NSEC3 operations
    root_zone_file.add_nsec3_domains(salt=DEFAULT_SALT, iterations=0)

    # And sign
    root_zone_file.sign()

    # Save the zone file, signed
    root_zone_file.to_file(ZONE_DIR, signed=True)
    if HAVE_SECONDARY_ZONE:
        root_zone_file.to_file(ZONE_DIR_SECOND_NS, signed=True)


def new_domain_use_case(
    subdomain: str,
    parent: str,  # absolute fqdn
    keys_options: List[KeysOption],
    nb_subdomains: int = 0,
    ns=None,
    signed: bool = True,
    wildcard_subdomain: bool = False,
    domain_specific_parameters: List[DomainSpecificParameters] = None,
) -> (Domain, str):
    """
    Generate a new domain according to the subdomain and parent
    """

    if ns is None:
        ns = ROOT_NS
    generated_domain_fqdn = subdomain + "." + parent
    generated_domain = Domain.generate(
        generated_domain_fqdn,
        nb_subdomain=nb_subdomains,
        wildcard_subdomain=wildcard_subdomain,
        specific_parameters=domain_specific_parameters,
    )
    generated_domain.set_ns(ns)
    generated_domain.set_soa(SOAContent(generated_domain_fqdn))
    if signed:
        for k in keys_options:
            generated_key = DnssecKeyInfo(
                DnssecKey.generate(algorithm=k.algorithm), k.type, origin_id=k.origin_id
            )
            generated_key.save(path=X3LD_KEY_DIR, fqdn=generated_domain_fqdn)
            generated_domain.add_key(generated_key)

    return generated_domain, generated_domain_fqdn


def handle_error(
    error: DnssecError,
    parent_use_case=None,
    children_use_case=None,
    grand_children_use_case=None,
    zone_parent=None,
    zone_children=None,
    zone_grand_children=None,
    zone_unsigned_children=None,
    error_list=None,
):
    if zone_parent:
        parent_nsec_params = get_nsec_parameters_from_zone(zone_parent)
    if zone_children:
        children_nsec_params = get_nsec_parameters_from_zone(zone_children)
    # Olivier's
    if error.error_type == DnssecErrorType.DIGEST_INVALID:
        modify_last_char_ds(children=zone_children, parent=zone_parent)
    elif error.error_type == DnssecErrorType.SIGNATURE_INVALID:
        modify_all_rrsigs(zone_children)
    elif error.error_type == DnssecErrorType.REMOVE_ONE_KSK:
        remove_one_ksk_from_the_children(children_use_case)
    elif error.error_type == DnssecErrorType.REMOVE_RRSIG_DNSKEY:
        remove_rrsig_ksk(zone_children, key_tags=children_use_case.get_list_ksk_tags())
    elif error.error_type == DnssecErrorType.LAST_NSEC_NOT_ZONE:
        change_apex_nsec(zone_children)
    elif error.error_type == DnssecErrorType.REMOVE_NSEC_AND_IP4_FOR_E_SUBDOMAIN:
        remove_record_type_for_a_subdomain(
            zone_children=zone_grand_children, rdtype=dns.rdatatype.A, subdomain="a"
        )
        remove_nsec(zone_children=zone_grand_children)
    elif error.error_type == DnssecErrorType.REMOVE_ALL_NSEC:
        remove_all_nsec_rr(zone_grand_children)
    elif error.error_type == DnssecErrorType.NO_CLOSEST_ENCLOSER:
        remove_last_nsec3_records(zone_children)
    elif error.error_type == DnssecErrorType.REMOVE_LAST_NSEC3:
        remove_last_nsec3_records(zone_children)
    elif error.error_type == DnssecErrorType.REMOVE_Q_SUBDOMAIN_NSEC:
        remove_nsec_for_a_specific_subdomain(zone_children, b"q")
    elif error.error_type == DnssecErrorType.REMOVE_RRSIG_OF_SUBDOMAIN:
        remove_all_subdomains_rrsig(zone_children)
    elif error.error_type == DnssecErrorType.REMOVE_RRSIG_KSK:
        remove_all_rrsig_ksk(zone_children, children_use_case)
    elif error.error_type == DnssecErrorType.REVOKE_ONE_KSK:
        # This error can be called multiple time
        # Will return True if it was possible
        revoke_one_ksk(children_use_case)
    elif error.error_type == DnssecErrorType.REVOKE_ONE_ZSK:
        # This error can be called multiple time
        # Will return True if it was possible
        revoke_one_zsk(children_use_case)
    elif error.error_type == DnssecErrorType.ADD_A_DS:
        add_a_ds_to_the_parent_zone(children_use_case.fqdn, zone_parent)

    elif error.error_type == DnssecErrorType.DNSKEY_MISSING_FROM_SERVERS:
        # Add a new key to children

        children_use_case.add_key(
            DnssecKeyInfo(
                key=DnssecKey.generate(algorithm=KeyAlgorithm.RSASHA256),
                type=KeyFlags.ZSK,
                origin_id="ERROR_HANDLER",
            )
        )

        # remove_a_zsk_from_the_children_for_secondary_server(zone_children)

    elif error.error_type == DnssecErrorType.REMOVE_RRSIG_FROM_AN_ALGO_DNSKEY:
        key_algos = children_use_case.get_list_keys_algo()
        ksk_algos = set(key_algos.get("ksk", []))
        zsk_algos = set(key_algos.get("zsk", []))
        additional_algo_in_zsks = zsk_algos - ksk_algos
        remove_rrsig_for_an_algo(zone_children, list(additional_algo_in_zsks))

    elif error.error_type == DnssecErrorType.REMOVE_RRSIG_FROM_AN_ALGO_DS:
        key_algos = children_use_case.get_list_keys_algo()
        ksk_algos = set(key_algos.get("ksk", []))
        zsk_algos = set(key_algos.get("zsk", []))
        additional_algo_in_ksks = ksk_algos - zsk_algos
        remove_rrsig_for_an_algo(zone_children, list(additional_algo_in_ksks))

    elif error.error_type == DnssecErrorType.REMOVE_RRSIG_ZSK:
        remove_all_rrsig_zsk(zone_children)
    elif error.error_type == DnssecErrorType.ADD_A_ZSK:
        add_a_zsk_to_children(
            children_use_case, key_type=KeyFlags.ZSK, alg=KeyAlgorithm.RSASHA256
        )

    # Ishtiaq's
    elif error.error_type == DnssecErrorType.NONZERO_ITER_COUNT:
        pass
    elif error.error_type == DnssecErrorType.EXPIRED_RRSIG:
        pass
    elif error.error_type == DnssecErrorType.NOT_YET_VALID_RRSIG:
        pass
    elif error.error_type == DnssecErrorType.ORIGINAL_TTL_EXCEEDED_RRSET:
        replace_rdata_and_rrsig(
            zone_children,
            owner_name="a." + zone_children.fqdn,
            type=dns.rdatatype.A,
            rrsig_ttl=20,
        )
        logger.logger.debug(zone_children)
    elif error.error_type == DnssecErrorType.ORIGINAL_TTL_EXCEEDED_RRSIG:
        replace_rdata_and_rrsig(
            zone_children,
            owner_name="a." + zone_children.fqdn,
            type=dns.rdatatype.AAAA,
            ttl=40,
            rrsig_ttl=60,
            is_original_ttl_exceeded_rrsig=True,
        )
    elif error.error_type == DnssecErrorType.TTL_BEYOND_EXPIRATION:
        replace_rdata_and_rrsig(
            zone_children,
            owner_name="d." + zone_children.fqdn,
            type=dns.rdatatype.A,
            ttl=2678400,
            rrsig_ttl=2678400,
            expiration=(
                datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=5)
            ).strftime("%Y%m%d%H%M%S"),
        )
    elif error.error_type == DnssecErrorType.EXISTING_NAME_COVERED:
        if children_nsec_params[0] == "NSEC":
            change_nsec_next(zone_children)
        else:
            change_nsec3_next(zone_children, children_nsec_params[1])
    elif error.error_type == DnssecErrorType.SIGNER_NOT_ZONE_IN:
        # TODO: pass parent zone zsk; handle it later, not priority
        replace_rdata_and_rrsig(
            zone_children,
            owner_name="d." + zone_children.fqdn,
            type=dns.rdatatype.AAAA,
            signer=zone_parent.fqdn,
        )
    elif error.error_type == DnssecErrorType.SIGNER_NOT_ZONE_OUT:
        # TODO: sign with ens zone's zsk; handle it later, not priority
        replace_rdata_and_rrsig(
            zone_children,
            owner_name="m." + zone_children.fqdn,
            type=dns.rdatatype.A,
            signer="ens." + DOMAIN,
        )
    elif error.error_type == DnssecErrorType.INVALID_NSEC3_HASH:
        # TODO: INVALID_RCODE comes up; handle it later, not priority
        owner_name = modify_last_bit_of_nsec3_hash(zone_children)
        replace_rdata_and_rrsig(
            zone_children, owner_name=owner_name, type=dns.rdatatype.NSEC3
        )
    elif error.error_type == DnssecErrorType.EXISTING_TYPE_NOT_IN_BITMAP:
        if children_nsec_params[0] == "NSEC":
            manipulate_nsec_bitmap(
                zone_children.fqdn, zone_children, error_list, which="bitmap"
            )
        else:
            manipulate_nsec3_bitmap(
                zone_children.fqdn,
                zone_children,
                error_list,
                children_nsec_params[1],
                which="bitmap",
            )
    elif error.error_type == DnssecErrorType.STYPE_IN_BITMAP:
        if children_nsec_params[0] == "NSEC":
            manipulate_nsec_bitmap(
                zone_children.fqdn, zone_children, error_list, which="bitmap"
            )
        else:
            manipulate_nsec3_bitmap(
                zone_children.fqdn,
                zone_children,
                error_list,
                children_nsec_params[1],
                which="bitmap",
            )
    elif error.error_type == DnssecErrorType.REFERRAL_WITH_DS:
        if parent_nsec_params[0] == "NSEC":
            manipulate_nsec_bitmap(
                zone_unsigned_children.fqdn, zone_parent, error_list, which="referral"
            )
        else:
            manipulate_nsec3_bitmap(
                zone_unsigned_children.fqdn,
                zone_parent,
                error_list,
                parent_nsec_params[1],
                which="referral",
            )
    elif error.error_type == DnssecErrorType.REFERRAL_WITH_SOA:
        # TODO: also comes with REFERRAL_WITH_DS. although this is an unintentional bug, it means we don't need to
        #  handle the case where both errors are present; so, not priority
        if parent_nsec_params[0] == "NSEC":
            manipulate_nsec_bitmap(
                zone_unsigned_children.fqdn, zone_parent, error_list, which="referral"
            )
        else:
            manipulate_nsec3_bitmap(
                zone_unsigned_children.fqdn,
                zone_parent,
                error_list,
                parent_nsec_params[1],
                which="referral",
            )
    elif error.error_type == DnssecErrorType.REFERRAL_WITHOUT_NS:
        if parent_nsec_params[0] == "NSEC":
            manipulate_nsec_bitmap(
                zone_unsigned_children.fqdn, zone_parent, error_list, which="referral"
            )
        else:
            manipulate_nsec3_bitmap(
                zone_unsigned_children.fqdn,
                zone_parent,
                error_list,
                parent_nsec_params[1],
                which="referral",
            )
    elif error.error_type == DnssecErrorType.MISSING_NSEC_FOR_WILDCARD:
        replace_rdata_and_rrsig(
            zone_children,
            owner_name="m." + zone_children.fqdn,
            type=dns.rdatatype.AAAA,
            labels=4,
        )
    elif (
        error.error_type == DnssecErrorType.RRSIG_LABELS_EXCEED_RRSET_OWNER_LABELS_NONWC
    ):
        replace_rdata_and_rrsig(
            zone_children,
            owner_name="z." + zone_children.fqdn,
            type=dns.rdatatype.A,
            labels=6,
        )
    elif error.error_type == DnssecErrorType.RRSIG_LABELS_EXCEED_RRSET_OWNER_LABELS_WC:
        replace_rdata_and_rrsig(
            zone_children,
            owner_name="*." + zone_children.fqdn,
            type=dns.rdatatype.A,
            labels=6,
        )  # for wildcard, provide label count + 1
    else:
        raise Exception("Unknown error")

    return (
        parent_use_case,
        children_use_case,
        grand_children_use_case,
        zone_parent,
        zone_children,
        zone_grand_children,
    )


def make_one_new_case(
    case_name: str,
    parent: str,
    dnssec_errors: DnssecErrors,
    parent_key_list: KeysOptions,
    children_key_list: KeysOptions,
    parent_nsec_option: NsecOption,
    children_nsec_option: NsecOption,
    parent_ns: List[str],
    child_ns: List[str],
    inception: str = DEFAULT_INCEPTION,
    expiration: str = DEFAULT_EXPIRATION,
    is_children_signed: bool = True,
    wildcard_subdomain: bool = False,
    nb_subdomains_children: int = 3,
    parent_use_case: Domain = None,
    children_use_case: Domain = None,
    parent_specific_parameters: List[DomainSpecificParameters] = None,
    children_specific_parameters: List[DomainSpecificParameters] = None,
    grand_children_use_case: Domain = None,
    signing_parameters: SigningParameters = SigningParameters(dict()),
    ds_map: dict = None,
):
    if not inception:
        inception = DEFAULT_INCEPTION
    if not expiration:
        expiration = DEFAULT_EXPIRATION
    # Create the two domains
    if parent_use_case is None:
        parent_use_case, parent_fqdn = new_domain_use_case(
            subdomain=case_name,
            parent=parent,
            keys_options=parent_key_list.list,
            nb_subdomains=3,
            ns=parent_ns,
            domain_specific_parameters=parent_specific_parameters,
        )
    else:
        parent_fqdn = parent_use_case.fqdn
    (
        unsigned_children_use_case,
        unsigned_children_domain_fqdn,
        zone_unsigned_children,
    ) = (None, None, None)
    if not is_children_signed:
        unsigned_children_use_case, unsigned_children_domain_fqdn = new_domain_use_case(
            subdomain="unsigned-children",
            parent=parent_fqdn,
            keys_options=children_key_list.list,
            nb_subdomains=1,
            ns=child_ns,
            signed=is_children_signed,
            wildcard_subdomain=wildcard_subdomain,
            domain_specific_parameters=children_specific_parameters,
        )
    if children_use_case is None:
        children_use_case, children_domain_fqdn = new_domain_use_case(
            subdomain="invalid-children",
            parent=parent_fqdn,
            keys_options=children_key_list.list,
            nb_subdomains=nb_subdomains_children,
            ns=child_ns,
            wildcard_subdomain=wildcard_subdomain,
            domain_specific_parameters=children_specific_parameters,
        )
    else:
        children_domain_fqdn = children_use_case.fqdn

    if grand_children_use_case is None:
        grand_children_use_case, grand_children_domain_fqdn = new_domain_use_case(
            subdomain="grand-children",
            parent=children_domain_fqdn,
            keys_options=[
                KeysOption(algorithm=KeyAlgorithm.RSASHA256, type=KeyFlags.ZSK),
                KeysOption(algorithm=KeyAlgorithm.RSASHA256, type=KeyFlags.KSK),
            ],
            nb_subdomains=3,
            ns=child_ns,
            domain_specific_parameters=[],
        )
    else:
        grand_children_domain_fqdn = grand_children_use_case.fqdn

    # handle errors after domain_creation
    for err in dnssec_errors.get_priorities_equal(DnssecPriority.AFTER_DOMAIN_CREATION):
        (
            parent_use_case,
            children_use_case,
            grand_children_use_case,
            zone_parent,
            zone_children,
            zone_grand_children,
        ) = handle_error(
            err,
            parent_use_case=parent_use_case,
            children_use_case=children_use_case,
            zone_children=None,
            zone_parent=None,
            grand_children_use_case=grand_children_use_case,
            zone_grand_children=None,
        )
    children_use_case.add_subdomain(grand_children_use_case)
    parent_use_case.add_subdomain(children_use_case)
    if unsigned_children_use_case:
        parent_use_case.add_subdomain(unsigned_children_use_case)
    zone_parent = ZonefileGenerator(
        parent_use_case,
        ttl=TTL,
        nameservers=parent_use_case.NS.get_nameservers(),
        ds_map=ds_map,
    )

    # handle errors after parent zone creation
    for err in dnssec_errors.get_priorities_equal(
        DnssecPriority.AFTER_PARENT_ZONEFILE_CREATION
    ):
        (
            parent_use_case,
            children_use_case,
            grand_children_use_case,
            zone_parent,
            zone_children,
            zone_grand_children,
        ) = handle_error(
            err,
            parent_use_case=parent_use_case,
            children_use_case=children_use_case,
            zone_children=None,
            zone_parent=zone_parent,
            grand_children_use_case=grand_children_use_case,
            zone_grand_children=None,
        )

    zone_parent.to_file(ZONE_DIR, signed=False)
    if HAVE_SECONDARY_ZONE:
        zone_parent.to_file(ZONE_DIR_SECOND_NS, signed=False)

    zone_children = ZonefileGenerator(
        children_use_case, ttl=TTL, nameservers=children_use_case.NS.get_nameservers()
    )
    if unsigned_children_use_case:
        zone_unsigned_children = ZonefileGenerator(
            unsigned_children_use_case,
            ttl=TTL,
            nameservers=unsigned_children_use_case.NS.get_nameservers(),
        )

    zone_grand_children = ZonefileGenerator(
        grand_children_use_case,
        ttl=TTL,
        nameservers=children_use_case.NS.get_nameservers(),
    )

    # handle errors after children zone creation
    for err in dnssec_errors.get_priorities_equal(
        DnssecPriority.AFTER_ZONEFILE_CREATION
    ):
        (
            parent_use_case,
            children_use_case,
            grand_children_use_case,
            zone_parent,
            zone_children,
            zone_grand_children,
        ) = handle_error(
            err,
            parent_use_case=parent_use_case,
            children_use_case=children_use_case,
            zone_children=zone_children,
            zone_parent=zone_parent,
            grand_children_use_case=grand_children_use_case,
            zone_grand_children=zone_grand_children,
        )

    zone_parent.to_file(ZONE_DIR, signed=False)
    zone_children.to_file(ZONE_DIR, signed=False)
    zone_grand_children.to_file(ZONE_DIR, signed=False)

    if zone_unsigned_children:
        zone_unsigned_children.to_file(ZONE_DIR, signed=False)
    if HAVE_SECONDARY_ZONE:
        zone_parent.to_file(ZONE_DIR_SECOND_NS, signed=False)
        zone_children.to_file(ZONE_DIR_SECOND_NS, signed=False)
        zone_grand_children.to_file(ZONE_DIR_SECOND_NS, signed=False)
        if zone_unsigned_children:
            zone_unsigned_children.to_file(ZONE_DIR_SECOND_NS, signed=False)

    for zone, nsec3options in [
        (zone_parent, parent_nsec_option),
        (zone_children, children_nsec_option),
        (zone_grand_children, children_nsec_option),
    ]:
        if nsec3options.nsec_version == NsecVersion.NSEC:
            zone.add_nsec_domains(ttl=TTL)
        elif nsec3options.nsec_version == NsecVersion.NSEC3:
            zone.add_nsec3_domains(
                salt=nsec3options.salt, iterations=nsec3options.nsec_iterations, ttl=TTL
            )
        elif nsec3options.nsec_version == NsecVersion.NO:
            # Do nothing
            pass
        else:
            raise Exception("Invalid NSEC option")

    # handle errors after NSEC/NSEC3
    for err in dnssec_errors.get_priorities_equal(DnssecPriority.AFTER_NSEC):
        (
            parent_use_case,
            children_use_case,
            grand_children_use_case,
            zone_parent,
            zone_children,
            zone_grand_children,
        ) = handle_error(
            err,
            parent_use_case=parent_use_case,
            children_use_case=children_use_case,
            zone_children=zone_children,
            zone_parent=zone_parent,
            zone_grand_children=zone_grand_children,
            grand_children_use_case=grand_children_use_case,
        )

    zone_parent.sign()
    zone_children.sign(
        expiration=expiration,
        inception=inception,
        signing_parameters=signing_parameters,
    )
    zone_grand_children.sign(expiration=expiration, inception=inception)

    # handle errors after signing
    referral_errors = False
    bitmap_errors = False
    error_list = [
        err.error_type
        for err in dnssec_errors.get_priorities_equal(DnssecPriority.AFTER_SIGNATURE)
    ]

    for err in dnssec_errors.get_priorities_equal(DnssecPriority.AFTER_SIGNATURE):
        # For efficiency, do not call manipulate bitmap multiple times for same type of error
        if err.error_type in {
            DnssecErrorType.REFERRAL_WITHOUT_NS,
            DnssecErrorType.REFERRAL_WITH_DS,
            DnssecErrorType.REFERRAL_WITH_SOA,
        }:
            if not referral_errors:
                referral_errors = True
            else:
                continue
        if err.error_type in {
            DnssecErrorType.EXISTING_TYPE_NOT_IN_BITMAP,
            DnssecErrorType.STYPE_IN_BITMAP,
        }:
            if not bitmap_errors:
                bitmap_errors = True
            else:
                continue
        (
            parent_use_case,
            children_use_case,
            grand_children_use_case,
            zone_parent,
            zone_children,
            zone_grand_children,
        ) = handle_error(
            err,
            parent_use_case=parent_use_case,
            children_use_case=children_use_case,
            zone_children=zone_children,
            zone_parent=zone_parent,
            zone_unsigned_children=zone_unsigned_children,
            error_list=error_list,
            zone_grand_children=zone_grand_children,
            grand_children_use_case=grand_children_use_case,
        )

    for err in dnssec_errors.get_priorities_equal(DnssecPriority.LAST_AFTER_SIGNATURE):
        (
            parent_use_case,
            children_use_case,
            grand_children_use_case,
            zone_parent,
            zone_children,
            zone_grand_children,
        ) = handle_error(
            err,
            parent_use_case=parent_use_case,
            children_use_case=children_use_case,
            zone_children=zone_children,
            zone_parent=zone_parent,
            zone_grand_children=zone_grand_children,
            grand_children_use_case=grand_children_use_case,
        )

    zone_parent.to_file(ZONE_DIR, signed=True)
    zone_children.to_file(ZONE_DIR, signed=True)
    zone_grand_children.to_file(ZONE_DIR, signed=True)
    if HAVE_SECONDARY_ZONE:
        zone_parent.to_file(ZONE_DIR_SECOND_NS, signed=True)
        zone_children.to_file(ZONE_DIR_SECOND_NS, signed=True)
        zone_grand_children.to_file(ZONE_DIR_SECOND_NS, signed=True)

    for err in dnssec_errors.get_priorities_equal(DnssecPriority.REDO_WHOLE_PROCESS):
        (
            parent_use_case,
            children_use_case,
            grand_children_use_case,
            zone_parent,
            zone_children,
            zone_grand_children,
        ) = handle_error(
            err,
            parent_use_case=parent_use_case,
            children_use_case=children_use_case,
            zone_children=zone_children,
            zone_parent=zone_parent,
            zone_unsigned_children=zone_unsigned_children,
            error_list=error_list,
            zone_grand_children=zone_grand_children,
            grand_children_use_case=grand_children_use_case,
        )
        # Resigning and rewriting the modified zone to only the secondary zone
        if HAVE_SECONDARY_ZONE:
            if err.error_type == DnssecErrorType.DNSKEY_MISSING_FROM_SERVERS:
                zone_children = ZonefileGenerator(
                    children_use_case,
                    ttl=TTL,
                    nameservers=children_use_case.NS.get_nameservers(),
                )

                if children_nsec_option.nsec_version == NsecVersion.NSEC:
                    zone_children.add_nsec_domains(ttl=TTL)
                elif children_nsec_option.nsec_version == NsecVersion.NSEC3:
                    zone_children.add_nsec3_domains(
                        salt=children_nsec_option.salt,
                        iterations=children_nsec_option.nsec_iterations,
                        ttl=TTL,
                    )
                elif children_nsec_option.nsec_version == NsecVersion.NO:
                    # Do nothing
                    pass

            zone_children.sign(expiration=expiration, inception=inception)
            zone_children.to_file(ZONE_DIR_SECOND_NS, signed=True)
            zone_grand_children.to_file(ZONE_DIR_SECOND_NS, signed=True)

    return [
        zone_parent,
        zone_children,
        zone_unsigned_children,
        parent_use_case,
        children_use_case,
        unsigned_children_use_case,
        grand_children_use_case,
        zone_grand_children,
    ]


def sanity_check_1(zone_name, dom2err, errcode):
    errcodes = get_errcodes(zone_name, dom2err)
    return errcode in errcodes


def sanity_check_2(zone_name, dom2err):
    errcodes = get_errcodes(zone_name, dom2err)
    return len(errcodes) == 0
