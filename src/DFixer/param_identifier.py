import random

from publicsuffixlist import PublicSuffixList

from ZReplicator import DnssecErrors
from config import PARENT_NS, CASE, DEFAULT_SALT, CHILD_NS, DOMAIN
from crypto import (
    KeyFlags,
    KeysOption,
    KeysOptions,
    get_random_algo_not_in_list,
    KeyAlgorithm,
    NsecVersion,
)
from crypto import key_algo_list_usable, key_algo_list_not_usable, NsecOption
from domaingenerator import DomainSpecificParameters, DomainInstruction
from grokreader import GrokData
from utils import get_errcodes
from utils.logging_utils import logger
from .errors import *
from .util import (
    find_out_dnskey_rrsig_key_tags,
    find_errors_in_analysis,
    identify_zone_name,
    get_parent_zone,
    populate_ds_map,
    get_doe_params,
    populate_key_map,
)


def create_key_option(dnskey_map) -> KeysOptions:
    key_list = []
    set_algo = set()
    for key in dnskey_map.keys():
        algorithm = dnskey_map[key][1]
        if dnskey_map[key][2] == 256 or dnskey_map[key][2] == 384:
            tp = KeyFlags.ZSK
        elif dnskey_map[key][2] == 257 or dnskey_map[key][2] == 385:
            tp = KeyFlags.KSK
        else:
            logger.logger.error("Wrong key flags", dnskey_map[key][2])
            raise Exception("Unknown key flags")
        set_algo.add(algorithm)
        key_list.append(KeysOption(algorithm=algorithm, type=tp, origin_id=key))

    algo_to_modify = set()
    for algo in set_algo:
        if algo in key_algo_list_not_usable:
            algo_to_modify.add(algo)

    map_algo = dict()
    algo_left = set(key_algo_list_usable) - set_algo
    if len(algo_left) < len(algo_to_modify):
        raise Exception("Not enough algorithm...")

    else:
        for algo in algo_to_modify:
            map_algo[algo] = algo_left.pop()

    for k in key_list:
        if k.algorithm in map_algo.keys():
            k.algorithm = map_algo[k.algorithm]

    return KeysOptions(key_list)


def load_nsec_option_from_doe_params(doe_params):
    if doe_params[0] == "NSEC":
        return NsecOption(nsec_version=NsecVersion.NSEC)
    elif doe_params[0] == "NSEC3":
        return NsecOption(
            nsec_version=NsecVersion.NSEC3,
            salt=DEFAULT_SALT,
            nsec_iterations=int(doe_params[1][2]),
        )


def identify_case_for_missing_sep_for_alg(analysis, zone_name, ds_map, dnskey_map):
    extraneous_ds_tags = []
    for key in ds_map:
        if ds_map[key][3] == "INDETERMINATE_NO_DNSKEY":
            extraneous_ds_tags.append(str(ds_map[key][0]))
    is_ksk_present = False
    for key in dnskey_map:
        if dnskey_map[key][2] == 257:
            is_ksk_present = True
            break
    if extraneous_ds_tags:
        if is_ksk_present:
            return "remove_a_ksk"
        else:
            return "add_a_ds"
    dnskey_rrsig_key_tags = find_out_dnskey_rrsig_key_tags(analysis, zone_name)
    absent_ksk_rrsig_tags = []
    for key in dnskey_map:
        if (
            dnskey_map[key][2] == 257
            and dnskey_map[key][0] not in dnskey_rrsig_key_tags
        ):
            absent_ksk_rrsig_tags.append(str(dnskey_map[key][0]))
    if absent_ksk_rrsig_tags:
        return "remove_dnskey_rrsig"
    #    return "could not identify"
    return "add_a_ds"


def identify_meta_parameters(
    id_,
    analysis,
    psl: PublicSuffixList = None,
    grok_data: GrokData = None,
    generated_for_artifacts=False,
):
    """
    Identify meta parameters to pass to main.py for emulating the errors in given analysis
    :return:
    """
    case = CASE  # + str(id_)
    query_domain = f"invalid-children.{case}.{DOMAIN.strip('.')}"
    qdomains = {query_domain}

    # Set defaults
    is_children_signed, wildcard_subdomain, inception, expiration = (
        True,
        False,
        None,
        None,
    )
    extra_qtypes = ""
    parent_ns = PARENT_NS
    child_ns = CHILD_NS
    parent_specific_domain_parameters = None
    children_specific_domain_parameters = None
    nb_subdomains = 4

    # Identify existing errors in the analysis
    dom2err = find_errors_in_analysis(analysis, psl=psl)
    logger.logger.debug("error", dom2err)

    children_zone_name = identify_zone_name(analysis)
    parent_zone_name = get_parent_zone(analysis, children_zone_name)
    logger.logger.debug("zone name", children_zone_name, parent_zone_name)

    if not parent_zone_name or not children_zone_name.endswith(parent_zone_name):
        return "Exception!!!Probably Delegated"

    if (
        "delegation" in analysis[parent_zone_name]
        and analysis[parent_zone_name]["delegation"].get("status", None) == "INSECURE"
        and not generated_for_artifacts
    ):
        return "Exception!!!Unsigned Parent Zone"

    # We can use this to construct DS status for the children zone
    children_ds_map = populate_ds_map(analysis, children_zone_name)
    parent_ds_map = populate_ds_map(analysis, parent_zone_name)
    logger.logger.debug(f"ds_parent : {parent_ds_map}")
    logger.logger.debug(f"ds_children : {children_ds_map}")

    # We can use this to construct parent_nsec_option and children_nsec_option
    children_zone_doe_params = get_doe_params(
        analysis
    )  # trying to get doe_params for the queried domain from descendant subdomain queries
    if (
        not children_zone_doe_params
    ):  # if not found, trying to get doe_params from inside the zone queries
        children_zone_doe_params = get_doe_params(analysis, zone=children_zone_name)
    # trying to find parent zone doe_parems from inside the parent zone queries
    parent_zone_doe_params = get_doe_params(analysis, zone=parent_zone_name)
    if not parent_zone_doe_params:
        parent_zone_doe_params = get_doe_params(
            analysis, zone=children_zone_name, ignore_ds_query=False
        )

    logger.logger.debug("children_doe_params", children_zone_doe_params)
    logger.logger.debug("parent_doe_params", parent_zone_doe_params)
    if not parent_zone_doe_params:
        parent_nsec_option = NsecOption(nsec_version=NsecVersion.NSEC)
    else:
        parent_nsec_option = load_nsec_option_from_doe_params(parent_zone_doe_params)
    if (
        not children_zone_doe_params
    ):  # NSEC not found in grok does not mean NSEC is not there, it might be that every record exists
        children_nsec_option = NsecOption(nsec_version=NsecVersion.NSEC)
    else:
        children_nsec_option = load_nsec_option_from_doe_params(
            children_zone_doe_params
        )

    # We can use this to construct parent_key_list and children_key_list
    children_dnskey_map = populate_key_map(
        analysis, children_zone_name, children_nsec_option
    )

    parent_dnskey_map = populate_key_map(analysis, parent_zone_name, parent_nsec_option)
    logger.logger.debug("dnskey_map_children", children_dnskey_map)
    logger.logger.debug("dnskey_map_parent", parent_dnskey_map)
    children_key_list = create_key_option(children_dnskey_map)
    parent_key_list = create_key_option(parent_dnskey_map)
    if not children_key_list.list:  # NO DNSKEY, so let's set it to NOOP
        children_nsec_option = NsecOption(nsec_version=NsecVersion.NO)

    if not parent_key_list.list:  # NO DNSKEY, so let's set it to NOOP

        parent_nsec_option = NsecOption(nsec_version=NsecVersion.NO)

    errors_list = []
    err_codes = get_errcodes(children_zone_name, dom2err)
    for errcode in err_codes:
        # Ishtiaq's
        if errcode == "NONZERO_NSEC3_ITERATION_COUNT":
            errors_list.append(nnic)
            # if children_nsec_option.nsec_version != NsecVersion.NSEC3:
            #     children_nsec_option = NsecOption(
            #         nsec_version=NsecVersion.NSEC3,
            #         nsec_iterations=10,
            #         salt=DEFAULT_SALT,
            #     )
            # if children_nsec_option.nsec_iterations <= 0:
            #     children_nsec_option = NsecOption(
            #         nsec_version=NsecVersion.NSEC3,
            #         nsec_iterations=10,
            #         salt=DEFAULT_SALT,
            #     )
        elif errcode == "EXPIRATION_IN_PAST":
            errors_list.append(exp)
            expiration = "20250324195202"
        elif errcode == "INCEPTION_IN_FUTURE":
            errors_list.append(inc)
            inception = "20250601000000"
        elif (
            errcode == "ORIGINAL_TTL_EXCEEDED"
            or errcode == "ORIGINAL_TTL_EXCEEDED_RRSET"
        ):
            errors_list.append(otert)
            qdomains.add("a." + query_domain)
        elif errcode == "ORIGINAL_TTL_EXCEEDED_RRSIG":
            errors_list.append(oterg)
            qdomains.add("a." + query_domain)
        elif errcode == "TTL_BEYOND_EXPIRATION":
            errors_list.append(texp)
            qdomains.add("d." + query_domain)
        elif errcode == "EXISTING_NAME_COVERED":
            errors_list.append(ens)
            qdomains.add("a." + query_domain)
        elif errcode == "SIGNER_NOT_ZONE":
            # since solution of both are same, no need to identify whether to go with snzi/snzo and just go with more severe one (snzo)
            # errors_list.append(snzi)
            errors_list.append(snzo)
            qdomains.add("m." + query_domain)
        elif errcode == "EXISTING_TYPE_NOT_IN_BITMAP":
            errors_list.append(enb)
        elif errcode == "STYPE_IN_BITMAP":
            errors_list.append(sib)
        elif errcode == "REFERRAL_WITH_DS":
            errors_list.append(rwd)
            qdomains.add(f"unsigned-children.{case}.{DOMAIN[:-1]}")
            is_children_signed = False
        elif errcode == "REFERRAL_WITH_SOA":
            errors_list.append(rws)
            qdomains.add(f"unsigned-children.{case}.{DOMAIN[:-1]}")
            is_children_signed = False
        elif errcode == "REFERRAL_WITHOUT_NS":
            errors_list.append(rwn)
            qdomains.add(f"unsigned-children.{case}.{DOMAIN[:-1]}")
            is_children_signed = False
        elif errcode == "MISSING_NSEC_FOR_WILDCARD":
            errors_list.append(mnw)
            qdomains.add("m." + query_domain)
        elif errcode == "RRSIG_LABELS_EXCEED_RRSET_OWNER_LABELS":
            errors_list.append(rlnwc)
            qdomains.add("z." + query_domain)
        # Olivier's
        elif errcode == "SIGNATURE_INVALID":
            if len(children_key_list.list) == 0:
                errors_list.append(add_a_zsk)
                errors_list.append(make_signature_invalid)
            else:
                # For reproduction purpose, does not make it random
                # since it does not matter much, we can randomly choose any of the two
                r = random.uniform(0, 1)

                errors_list.append(make_signature_invalid)

        elif errcode == "DIGEST_INVALID":
            errors_list.append(make_digest_invalid)
        elif errcode == "MISSING_SEP_FOR_ALG":
            error_case = identify_case_for_missing_sep_for_alg(
                analysis, children_zone_name, children_ds_map, children_dnskey_map
            )
            if len(children_ds_map) > len(children_dnskey_map):
                for j in range(0, len(children_ds_map) - len(children_dnskey_map)):
                    # if error_case == "add_a_ds":
                    errors_list.append(
                        add_a_ds
                    )  # Case 1: extraneous DS, DS exists but no DNSKEY is present
            for j in children_ds_map:
                if children_ds_map[j][3] == "INDETERMINATE_NO_DNSKEY":
                    if add_a_ds not in errors_list:
                        errors_list.append(add_a_ds)
                    break

            if error_case == "remove_a_ksk":
                errors_list.append(
                    remove_a_ksk
                )  # Case 2: extraneous DS, DS exists but no corresponding DNSKEY, other DNSKEYs exist (msa)

            if error_case == "add_a_ds":
                errors_list.append(add_a_ds)
            elif error_case == "remove_dnskey_rrsig":
                errors_list.append(
                    remove_dnskey_rrsig
                )  # Case 3: DS exists, DNSKEY exists, but no KSK RRSIG exists (nosep)
        elif errcode == "LAST_NSEC_NEXT_NOT_ZONE":
            errors_list.append(nsec_remove_apex)
            qdomains.add("zz." + query_domain)
        elif errcode == "MISSING_NSEC_FOR_NODATA":
            errors_list.append(remove_nsec_for_nodata)  # untested
            qdomains.add("a.grand-children." + query_domain)
        elif errcode == "MISSING_NSEC_FOR_NXDOMAIN":
            errors_list.append(remove_all_nsec)
            qdomains.add("nxsubdomain_test.grand-children." + query_domain)
        elif errcode == "NO_CLOSEST_ENCLOSER":
            errors_list.append(remove_last_nsec3_parent_and_children)
            qdomains.add("zzzz." + query_domain)
            if parent_nsec_option.nsec_version != NsecVersion.NSEC3:
                parent_nsec_option = NsecOption(
                    nsec_version=NsecVersion.NSEC3, nsec_iterations=0, salt=DEFAULT_SALT
                )
            if children_nsec_option.nsec_version != NsecVersion.NSEC3:
                children_nsec_option = NsecOption(
                    nsec_version=NsecVersion.NSEC3, nsec_iterations=0, salt=DEFAULT_SALT
                )
        elif errcode == "NO_NSEC3_MATCHING_SNAME":
            errors_list.append(remove_last_nsec3)
            qdomains.add("f." + query_domain)
            if parent_nsec_option.nsec_version != NsecVersion.NSEC3:
                parent_nsec_option = NsecOption(
                    nsec_version=NsecVersion.NSEC3, nsec_iterations=0, salt=DEFAULT_SALT
                )
            if children_nsec_option.nsec_version != NsecVersion.NSEC3:
                children_nsec_option = NsecOption(
                    nsec_version=NsecVersion.NSEC3, nsec_iterations=0, salt=DEFAULT_SALT
                )
            children_specific_domain_parameters = [
                DomainSpecificParameters(
                    domain_instruction=DomainInstruction.ADD_SUBDOMAIN,
                    options={
                        "subdomain": "f",
                        "nb_subdomains": 3,
                        "additional_records": False,
                    },
                ),
                DomainSpecificParameters(
                    domain_instruction=DomainInstruction.REMOVE_A_RECORD,
                    options={"subdomain": "f"},
                ),
            ]
        elif errcode == "NO_NSEC_MATCHING_SNAME":
            errors_list.append(
                remove_subdomain_q_nsec_record
            )  # Specific parameters here
            qdomains.add("q." + query_domain)
            children_specific_domain_parameters = [
                DomainSpecificParameters(
                    domain_instruction=DomainInstruction.ADD_SUBDOMAIN,
                    options={
                        "subdomain": "q",
                        "nb_subdomains": 2,
                        "additional_records": False,
                    },
                ),
            ]
        elif errcode == "MISSING_RRSIG":
            if len(children_key_list.list) == 0:
                children_key_list.list.append(
                    KeysOption(
                        algorithm=KeyAlgorithm.RSASHA256,
                        type=KeyFlags.KSK,
                        origin_id="CHILD_ERROR",
                    )
                )
            errors_list.append(remove_all_sub_rrsig)
            qdomains.add("a." + query_domain)
        elif errcode == "MISSING_RRSIG_FOR_ALG_DNSKEY":
            errors_list.append(missing_rrsig_for_alg_dnskey)
            # Add a ZSK with different algo
            new_algo = get_random_algo_not_in_list(
                [k.algorithm for k in children_key_list.list]
            )
            children_key_list.list.append(
                KeysOption(
                    algorithm=new_algo, type=KeyFlags.ZSK, origin_id="CHILD_ERROR"
                )
            )
        elif errcode == "DNSKEY_REVOKED_DS":
            errors_list.append(revoke_a_ksk)
        elif errcode == "DNSKEY_REVOKED_RRSIG":
            errors_list.append(revoke_a_zsk)
        elif errcode == "DNSKEY_MISSING_FROM_SERVERS":
            errors_list.append(make_a_dnskey_missing_from_one_server)
            # child_ns = [NS1, NS3]
        elif errcode == "MISSING_RRSIG_FOR_ALG_DS":
            errors_list.append(missing_rrsig_for_alg_ds)
            # Add a ZSK with different algo
            new_algo = get_random_algo_not_in_list(
                [k.algorithm for k in children_key_list.list]
            )
            children_key_list.list.append(
                KeysOption(
                    algorithm=new_algo, type=KeyFlags.KSK, origin_id="ERROR_HANDLER"
                )
            )
        elif errcode == "NO_SEP":
            pass
        else:
            logger.logger.error(f"The error '{errcode}' is not in handled by DFixer")

    return (
        case,
        DOMAIN,
        DnssecErrors(errors_list=errors_list),
        parent_key_list,
        children_key_list,
        parent_nsec_option,
        children_nsec_option,
        parent_ns,
        child_ns,
        inception,
        expiration,
        is_children_signed,
        wildcard_subdomain,
        nb_subdomains,
        parent_specific_domain_parameters,
        children_specific_domain_parameters,
        qdomains,
        extra_qtypes,
        children_ds_map,
    )
