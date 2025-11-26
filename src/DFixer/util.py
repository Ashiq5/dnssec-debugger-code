import json
import os
import subprocess
from collections import defaultdict
from datetime import datetime, timezone

from publicsuffixlist import PublicSuffixList

from config import (
    GENERATED_GROK_PATH,
    DNSVIZ_ANALYSIS_CMD,
    DOMAIN,
    NSEC3_KEY_NOT_USED_PATH,
)
from crypto.dnssec import NsecOption, NsecVersion
from utils import DEFAULT_ALGORITHM_NUMBER, CAT
from utils.logging_utils import logger


def get_dnsviz_validation_cmd(qname, extra_args):
    temp = DNSVIZ_ANALYSIS_CMD.replace("<root>", DOMAIN)
    temp = temp.replace("<name>", qname)
    temp = temp.replace("<extra_args>", extra_args)
    return temp


def run_dnsviz_validation(cmd):
    logger.logger.debug(f"Running command {cmd} \n")
    logger.logger.info("Running DNSViz probe")
    result = subprocess.run(cmd, shell=True, capture_output=True)
    if not os.path.exists(GENERATED_GROK_PATH):
        raise Exception("Error in executing command: " + str(result.stderr))


def load_grok(PATH=GENERATED_GROK_PATH):
    return json.load(open(PATH))


def parse_dict_for_errors(d, parent_keys=None, path2error=None):
    if path2error is None:
        path2error = {}
    if parent_keys is None:
        parent_keys = []
    for key, value in d.items():
        if key == "errors":
            # Print the value of "errors" along with the parent keys leading to it
            path = " -> ".join(parent_keys + [key])
            # print(f"Path: {path} -> Value: {value}")
            path2error[path] = value
        elif isinstance(value, dict):
            # Recursively search in nested dictionaries
            parse_dict_for_errors(value, parent_keys + [key], path2error)
        elif isinstance(value, list):
            # Search within lists and handle dictionaries inside lists
            for i, item in enumerate(value):
                if isinstance(item, dict):
                    parse_dict_for_errors(
                        item, parent_keys + [key + f"[{i}]"], path2error
                    )
    return path2error


def find_errors_in_analysis(analysis, psl: PublicSuffixList = None):
    keys = list(analysis.keys())
    dom2err = {}
    for key in keys:
        if "." not in key[:-1]:  # excluding root and TLD
            continue
        if (
            psl and psl.publicsuffix(key[:-1]) == key[:-1]
        ):  # publicsuffix TLD. so, ignore
            continue
        dom2err[key] = parse_dict_for_errors(analysis[key], path2error={})
    return dom2err


def populate_ds_map(analysis, zone):
    ds_map = {}
    if zone in analysis and "delegation" in analysis[zone]:
        if "ds" in analysis[zone]["delegation"]:
            ds_records = analysis[zone]["delegation"]["ds"]
            for ds in ds_records:
                ds_map[ds["id"]] = (
                    ds["key_tag"],
                    ds["algorithm"],
                    ds["digest_type"],
                    ds["status"],
                )
    return ds_map


def populate_key_map(analysis, zone, nsec_option: NsecOption = None):
    dnskey_map = {}
    zones = set()
    if zone in analysis and "dnskey" in analysis[zone]:
        dnskey_records = analysis[zone]["dnskey"]
        for dnskey in dnskey_records:
            if (
                nsec_option
                and nsec_option.nsec_version == NsecVersion.NSEC3
                and dnskey["algorithm"] < 7
            ):
                if zone not in zones:
                    f = open(NSEC3_KEY_NOT_USED_PATH, "a")
                    f.write(zone + "\n")
                    f.close()
                algorithm = DEFAULT_ALGORITHM_NUMBER
                zones.add(zone)
            else:
                algorithm = dnskey["algorithm"]
            dnskey_map[dnskey["id"]] = (
                dnskey["key_tag"],
                algorithm,
                dnskey["flags"],
                dnskey["key_length"],
                dnskey.get("key_tag_pre_revoke"),
            )
    return dnskey_map


def get_key_params(dnskey_map, kt):
    for id_ in dnskey_map:
        if dnskey_map[id_][0] == kt:
            return dnskey_map[id_]
    return


def check_if_zsk_exists_for_this_algo(dnskey_map, algo_numeric):
    for id_ in dnskey_map:
        logger.logger.debug("Checking if zsk exists, ", dnskey_map[id_], algo_numeric)
        if dnskey_map[id_][1] == algo_numeric and dnskey_map[id_][2] == 256:
            return True
    return False


def identify_zone_name(analysis):
    keys = list(analysis.keys())
    keys = sorted(keys, key=lambda v: len(v), reverse=True)
    logger.logger.debug(keys)
    for key in keys:
        if "zone" in analysis[key]:
            return key


def sanity_checker_for_zone(analysis, zone):
    if "zone" not in analysis[zone]:
        logger.logger.error(
            "'zone' key not present at "
            + zone
            + ". Please contact the developer with the grok file."
        )
        # sys.exit()


def identify_revoked_zone_keys(dnskey_map):
    l = []
    for id_ in dnskey_map:
        if dnskey_map[id_][2] == 384:
            l.append(id_)
    return l


def identify_non_revoked_zone_keys(dnskey_map):
    l = []
    for id_ in dnskey_map:
        if dnskey_map[id_][2] == 256:
            l.append(id_)
    return l


def identify_revoked_zone_sep_keys(dnskey_map):
    l = []
    for id_ in dnskey_map:
        if dnskey_map[id_][2] == 385:
            l.append(id_)
    return l


def identify_auth_servers(analysis, zone):
    auth_servers = []
    if "servers" in analysis[zone]["zone"]:
        servers = analysis[zone]["zone"]["servers"]
        for server in servers:
            if "auth" in servers[server]:
                auth_servers.append((server, servers[server]["auth"]))
        return auth_servers
    else:
        logger.logger.error(
            "'servers' key does not exist in "
            + zone
            + ". Please contact the developer with the grok file."
        )
        # sys.exit()


def identify_erroneous_servers(analysis):
    erroneous_servers = []
    keys = list(analysis.keys())
    keys = sorted(keys, key=lambda v: len(v), reverse=True)
    for key in keys:
        if "dnskey" in analysis[key]:
            dnskey_records = analysis[key]["dnskey"]
            for dnskey in dnskey_records:
                if "errors" in dnskey:
                    for error in dnskey["errors"]:
                        if error["code"] == "DNSKEY_MISSING_FROM_SERVERS":
                            erroneous_servers.extend(error["servers"])
            return erroneous_servers


def identify_invalid_keys(analysis):
    erroneous_keys = []
    keys = list(analysis.keys())
    keys = sorted(keys, key=lambda v: len(v), reverse=True)
    for key in keys:
        if "dnskey" in analysis[key]:
            dnskey_records = analysis[key]["dnskey"]
            for dnskey in dnskey_records:
                if "errors" in dnskey:
                    for error in dnskey["errors"]:
                        if "DNSKEY_BAD_LENGTH" in error["code"]:
                            erroneous_keys.append(dnskey["id"])
            return erroneous_keys


def get_hashing_algo_ds(ds_map, kt):
    for id_ in ds_map:
        if ds_map[id_][0] == kt:
            return ds_map[id_][2]
    return


def get_doe_params(analysis, zone=None, ignore_ds_query=True):
    keys = list(analysis.keys())
    keys = sorted(keys, key=lambda v: len(v), reverse=True)
    if not zone:
        key = keys[0]  # just checking the latest domain suffices
    else:
        key = zone
    if "queries" in analysis[key]:
        queries = analysis[key]["queries"]
        for qr in queries:
            if ignore_ds_query and qr == key + "/IN/DS":
                continue
            elif not ignore_ds_query:
                if qr != key + "/IN/DS":
                    continue
            doe_proofs = None
            data = analysis[key]["queries"][qr]
            if "answer" in data:
                answers = analysis[key]["queries"][qr]["answer"]
            elif "nodata" in data:
                doe_proofs = analysis[key]["queries"][qr]["nodata"]
            elif "nxdomain" in data:
                doe_proofs = analysis[key]["queries"][qr]["nxdomain"]
            else:  # it should not be reached
                continue
            if doe_proofs:
                for nodata in doe_proofs:
                    if "proof" in nodata:
                        proofs = nodata["proof"]
                        for proof in proofs:
                            if "nsec" in proof:
                                return "NSEC", None
                            if "nsec3" in proof:
                                if len(proof["nsec3"]) > 0:
                                    if "rdata" in proof["nsec3"][0]:
                                        if len(proof["nsec3"][0]["rdata"]) > 0:
                                            nsec3param = proof["nsec3"][0]["rdata"][
                                                0
                                            ].split()[0:4]
                                            return "NSEC3", (nsec3param)
    else:
        if "status" in analysis[key] and analysis[key]["status"] in {
            "INVALID",
            "INDETERMINATE",
        }:
            logger.logger.error(
                "Status of "
                + key
                + " is "
                + analysis[key]["status"]
                + ". Please fix this and check back with our pipeline."
            )
            # sys.exit()
    return


def identify_missing_algorithm(dom2err):
    missing_algos = defaultdict(list)
    for domain in dom2err:
        for path in dom2err[domain]:
            for err in dom2err[domain][path]:
                if err["code"] == "MISSING_RRSIG_FOR_ALG_DNSKEY":
                    rrset = path.split("->")[1]
                    missing_algo = (
                        err["description"]
                        .split("The DNSKEY RRset for the zone included algorithm")[1]
                        .split(",")[0]
                    )
                    missing_algos[missing_algo].append(rrset)
    return missing_algos


def identify_delegated_names(dom2err, code):
    delegated_names = []
    for domain in dom2err:
        for path in dom2err[domain]:
            for err in dom2err[domain][path]:
                if err["code"] == code:
                    rrset = path.split("->")[1]
                    if "/" in rrset:
                        rrname = rrset.split("/")[0]
                        delegated_names.append(rrname)
    return delegated_names


def calc_date_diff(i, e):
    fmt = "%Y-%m-%d %H:%M:%S"
    dt1 = datetime.strptime(i.replace(" UTC", ""), fmt).replace(tzinfo=timezone.utc)
    dt2 = datetime.strptime(e.replace(" UTC", ""), fmt).replace(tzinfo=timezone.utc)

    # Compute the difference in seconds
    diff = (dt2 - dt1).total_seconds()
    return diff


def get_ttl_and_signature_validity(analysis):
    keys = list(analysis.keys())
    keys = sorted(keys, key=lambda v: len(v), reverse=True)
    key = keys[0]  # just checking the latest domain suffices
    queries = analysis[key]["queries"]
    # rrsig_ttls = set()
    # rrsig_validities = set()
    record_ttl, rrsig_ttl, rrsig_validity = None, None, None
    for qr in queries:
        doe_statuses = []
        data = analysis[key]["queries"][qr]
        if "answer" in data:
            answers = analysis[key]["queries"][qr]["answer"]
            for answer in answers:
                record_ttl = answer["ttl"]
                for rrsig in answer.get("rrsig", []):
                    if "errors" in rrsig:
                        for err in rrsig["errors"]:
                            if err["code"] == "TTL_BEYOND_EXPIRATION":
                                # rrsig_ttls.add(rrsig['ttl'])
                                # rrsig_validities.add(calc_date_diff(rrsig['inception'], rrsig['expiration']))
                                # break
                                return (
                                    record_ttl,
                                    rrsig["ttl"],
                                    calc_date_diff(
                                        rrsig["inception"], rrsig["expiration"]
                                    ),
                                )
        elif "nxdomain" in data:
            doe_statuses.append("nxdomain")
        elif "nodata" in data:
            doe_statuses.append("nodata")
        if doe_statuses:
            for doe_status in doe_statuses:
                doe_queries = analysis[key]["queries"][qr][doe_status]
                for doe_query in doe_queries:
                    if "proof" in doe_query:
                        proofs = doe_query["proof"]
                        for proof in proofs:
                            if "nsec" in proof:
                                doe = "nsec"
                            elif "nsec3" in proof:
                                doe = "nsec3"
                            else:
                                doe = None
                            if doe:
                                for nsec in proof[doe]:
                                    record_ttl = nsec["ttl"]
                                    for rrsig in nsec["rrsig"]:
                                        if "errors" in rrsig:
                                            for err in rrsig["errors"]:
                                                if (
                                                    err["code"]
                                                    == "TTL_BEYOND_EXPIRATION"
                                                ):
                                                    # rrsig_ttls.add(rrsig['ttl'])
                                                    # rrsig_validities.add(calc_date_diff(rrsig['inception'], rrsig['expiration']))
                                                    # break
                                                    return (
                                                        record_ttl,
                                                        rrsig["ttl"],
                                                        calc_date_diff(
                                                            rrsig["inception"],
                                                            rrsig["expiration"],
                                                        ),
                                                    )
    return record_ttl, rrsig_ttl, rrsig_validity


def find_out_dnskey_rrsig_key_tags(analysis, zone):
    if zone not in analysis:
        logger.logger.error(
            "Zone itself is not present in analysis. Please contact the developer with the grok file."
        )
        # sys.exit()
        return []
    queries = analysis[zone]["queries"]
    qr = zone + "/IN/DNSKEY"
    if qr not in queries:
        logger.logger.error(
            "No DNSKEY query is present in analysis. Please contact the developer with the grok file."
        )
        # sys.exit()
        return []
    data = analysis[zone]["queries"][qr]
    dnskey_rrsigs = []
    if "answer" in data:
        answers = analysis[zone]["queries"][qr]["answer"]
        for answer in answers:
            for rrsig in answer.get("rrsig", []):
                dnskey_rrsigs.append(rrsig["key_tag"])
    return dnskey_rrsigs


def generate_resign_command(
    zone_name,
    doe_params=None,
    smart_signing=True,
    expiration=None,
    ignore_ksk=False,
    optout_flag=None,
    output_flag=True,
):
    resign_command = "`cd <key_dir> && dnssec-signzone -N INCREMENT "
    if doe_params and doe_params != "NSEC" and doe_params[0] == "NSEC3":
        # nsec3_algorithm = doe_params[1][0]
        flags = doe_params[1][1]
        # iter_count = doe_params[1][2]
        salt = doe_params[1][3]
        if optout_flag or flags == "1":  # turn on optout flag
            resign_command += "-3 " + salt + " -A "
        elif flags == "0":  # turn off optout flag
            resign_command += "-3 " + salt + " "
        else:
            logger.logger.error(
                "OptOut flag value cannot be "
                + flags
                + ". Please check your zone parameter. If you feel they are correct, please contact the developer with the grok file."
            )
            # sys.exit()
    if smart_signing:
        resign_command += "-S "
    if expiration:
        resign_command += "-e now+<validity_interval_in_seconds> "
    if ignore_ksk:
        resign_command += "-z "
    if output_flag:
        resign_command += "-f <zone_dir/signed_zone_file> "
    resign_command += "-o " + zone_name + " -t <zone_dir/unsigned_zone_file>`"
    return resign_command


def get_parent_zone(analysis, zone):
    keys = list(analysis.keys())
    keys = sorted(keys, key=lambda v: len(v), reverse=True)
    for key in keys:
        if key == zone or len(key) > len(zone):
            continue
        if "zone" not in analysis[key]:
            continue
        return key


def update_server(case):
    commands = [
        ["rndc", "-k", "/data/bind1/rndc.key", "-p", "953", "reload"],
        ["rndc", "-k", "/data/bind2/rndc.key", "-p", "954", "reload"],
    ]

    for cmd in commands:
        try:
            res_cmd = subprocess.run(cmd, check=True, capture_output=True, text=True)
            logger.logger.debug(f"\n[✓] {' '.join(cmd)}\n{res_cmd.stdout}")
        except subprocess.CalledProcessError as e:
            logger.logger.debug(f"[✗] {' '.join(cmd)} failed:\n{e.stderr}")
    return


independent_errors = (
        [
            "DNSKEY_MISSING_FROM_SERVERS",
            "DNSKEY_REVOKED_DS",
            "DNSKEY_REVOKED_RRSIG",
            "DNSKEY_BAD_LENGTH_ECDSA256",
            "DNSKEY_BAD_LENGTH_ECDSA384",
            "DNSKEY_ZERO_LENGTH",
        ]
        + ["MISSING_RRSIG_FOR_ALG_DNSKEY"]  # ?
        + ["DIGEST_INVALID", "MISSING_SEP_FOR_ALG"]
        + [
            "MISSING_RRSIG",
            "SIGNATURE_INVALID",
            "RRSIG_BAD_LENGTH_ECDSA256",
            "RRSIG_BAD_LENGTH_ECDSA384",
            "SIGNER_NOT_ZONE",
            "RRSIG_LABELS_EXCEED_RRSET_OWNER_LABELS",
        ]
        + ["INCEPTION_IN_FUTURE", "EXPIRATION_IN_PAST"]
        + [
            "TTL_BEYOND_EXPIRATION",
            "ORIGINAL_TTL_EXCEEDED",
            "ORIGINAL_TTL_EXCEEDED_RRSET",
            "ORIGINAL_TTL_EXCEEDED_RRSIG",
        ]
        + list(CAT["DoE"])
)
dependent_errors = {"MISSING_RRSIG_FOR_ALG_DS", "NO_SEP", "REVOKED_NOT_SIGNING"}


def pick_topologically_first(codes, ignored_errcodes):
    subset_of_independent_errors = codes.difference(dependent_errors)
    subset_of_independent_errors = [
        err for err in subset_of_independent_errors if err in independent_errors
    ]
    # Build a lookup dict that maps each item to its position in master_list
    index_map = {item: i for i, item in enumerate(independent_errors)}
    # Sort subset using the order defined in master_list
    ordered_subset = sorted(subset_of_independent_errors, key=lambda x: index_map[x])
    if ordered_subset:
        return ordered_subset[0]
    else:
        if not codes:
            if ignored_errcodes:
                logger.logger.info(
                    "Your zone is configured properly :) although few misconfigurations exist in your zone ancestors. Please contact the administrator of the respective ancestor zones to resolve their issues."
                )
                return
            else:
                logger.logger.info(
                    "No misconfigurations to resolve. Your zone is configured properly :)"
                )
                return
        else:
            logger.logger.info(
                "You have some misconfiguration(s): "
                + ",".join(codes)
                + " in your DNSSEC setup. Unfortunately, our pipeline does not yet cover them. Please contact the developer for updates regarding these."
            )
            return


def get_topological_ordering(codes, ignored_errcodes):
    subset_of_independent_errors = codes.difference(dependent_errors)
    subset_of_independent_errors = [
        err for err in subset_of_independent_errors if err in independent_errors
    ]
    # Build a lookup dict that maps each item to its position in master_list
    index_map = {item: i for i, item in enumerate(independent_errors)}
    # Sort subset using the order defined in master_list
    ordered_subset = sorted(subset_of_independent_errors, key=lambda x: index_map[x])
    if ordered_subset:
        return ordered_subset
    else:
        if not codes:
            if ignored_errcodes:
                logger.logger.info(
                    "Your zone is configured properly :) although few misconfigurations exist in your zone ancestors. Please contact the administrator of the respective ancestor zones to resolve their issues."
                )
                return
            else:
                logger.logger.info(
                    "No misconfigurations to resolve. Your zone is configured properly :)"
                )
                return
        else:
            logger.logger.info(
                "You have some misconfiguration(s): "
                + ",".join(codes)
                + " in your DNSSEC setup. Unfortunately, our pipeline does not yet cover them. Please contact the developer for updates regarding these."
            )
            return


def get_error_explanation(errcodes):
    explanations = [
        "Your zone is missing non-existence proof for certain record(s).",
        "Your zone has bad non-existence proof for certain record(s).",
        "Your zone has inconsistent ancestry setup for non-existent domain. This means query for a parent domain "
        "returns NXDOMAIN while query for a corresponding subdomain returns NOERROR which is contradictory.",
        "Your zone has incorrect closest encloser proof.",
        "Your zone has incorrect type bitmap in NSEC/NSEC3 record(s).",
        "Your zone has incorrect opt-out flag.",
        "Your zone has invalid NSEC3 hash.",
        "Your zone has invalid NSEC3 owner name.",
        "Last NSEC record in your zone does not point to the zone apex.",
        "Your zone has nonzero NSEC3 iteration count.",
        "Your zone has unsupported NSEC3 algorithm.",
        "Your zone has signature(s) with incorrect length.",
        "Your zone has signature(s) with labels field that exceed the number of labels in the RRset owner name.",
        "Your zone has invalid signature(s).",
        "Your zone has missing signature(s) for certain record(s).",
        "Your zone has signature(s) with incorrect signer that does not belong to your zone.",
        "Your zone has incomplete algorithm setup. This means a DNSKEY algorithm used by your zone is not consistently present in all signature(s) or does not align with the parent zone’s DS record(s).",
        "Your zone has incorrect/mismatched original TTL value.",
        "Your zone has record(s) with TTL that goes beyond it's corresponding signature expiration. This means an expired signature may exist in the resolver's cache if the record is not evicted.",\
        "Your zone has DNSKEY(s) with REVOKED bit set.",
        "Your zone has DNSKEY(s) with bad length.",
        "Authoritative servers for your zone serve inconsistent DNSKEY records.",
        "Your zone has expired signature(s).",
        "Your zone has signature(s) with inception time in future.",
        "Your zone has an invalid digest for the associated DNSKEY.",
        "Your zone has DS record(s) referencing a key algorithm not actually present in the zone."
    ]
    err2expl = {
        "MISSING_NSEC_FOR_NODATA": explanations[0],
        "MISSING_NSEC_FOR_NXDOMAIN": explanations[0],
        "MISSING_NSEC_FOR_WILDCARD": explanations[0],
        "NO_NSEC_MATCHING_SNAME": explanations[1],
        "NO_NSEC3_MATCHING_SNAME": explanations[1],
        "SNAME_COVERED": explanations[1],
        "SNAME_NOT_COVERED": explanations[1],
        "WILDCARD_COVERED": explanations[1],
        "WILDCARD_NOT_COVERED": explanations[1],
        "EXISTING_NAME_COVERED": explanations[1],
        "INCONSISTENT_NXDOMAIN_ANCESTOR": explanations[2],
        "NO_CLOSEST_ENCLOSER": explanations[3],
        "NEXT_CLOSEST_ENCLOSER_NOT_COVERED": explanations[3],
        "EXISTING_TYPE_NOT_IN_BITMAP": explanations[4],
        "REFERRAL_WITHOUT_NS": explanations[4],
        "REFERRAL_WITH_DS": explanations[4],
        "REFERRAL_WITH_SOA": explanations[4],
        "STYPE_IN_BITMAP": explanations[4],
        "OPT_OUT_FLAG_NOT_SET": explanations[5],
        "INVALID_NSEC3_HASH": explanations[6],
        "INVALID_NSEC3_OWNER_NAME": explanations[7],
        "LAST_NSEC_NEXT_NOT_ZONE": explanations[8],
        "NONZERO_NSEC3_ITERATION_COUNT": explanations[9],
        "UNSUPPORTED_NSEC3_ALGORITHM": explanations[10],
        "RRSIG_BAD_LENGTH_ECDSA256": explanations[11],
        "RRSIG_BAD_LENGTH_ECDSA384": explanations[11],
        "RRSIG_LABELS_EXCEED_RRSET_OWNER_LABELS": explanations[12],
        "SIGNATURE_INVALID": explanations[13],
        "MISSING_RRSIG": explanations[14],
        "SIGNER_NOT_ZONE": explanations[15],
        "MISSING_RRSIG_FOR_ALG_DNSKEY": explanations[16],
        "ORIGINAL_TTL_EXCEEDED_RRSET": explanations[17],
        "ORIGINAL_TTL_EXCEEDED_RRSIG": explanations[17],
        "TTL_BEYOND_EXPIRATION": explanations[18],
        "DNSKEY_REVOKED_RRSIG": explanations[19],
        "DNSKEY_REVOKED_DS": explanations[19],
        "DNSKEY_BAD_LENGTH_ECDSA256": explanations[20],
        "DNSKEY_BAD_LENGTH_ECDSA384": explanations[20],
        "DNSKEY_ZERO_LENGTH": explanations[20],
        "DNSKEY_MISSING_FROM_SERVERS": explanations[21],
        "EXPIRATION_IN_PAST": explanations[22],
        "INCEPTION_IN_FUTURE": explanations[23],
        "DIGEST_INVALID": explanations[24],
        "MISSING_SEP_FOR_ALG": explanations[25],
    }
    res = []
    ordered_errcodes = get_topological_ordering(errcodes, set())
    for errcode in ordered_errcodes:
        if errcode in err2expl:
            res.append(err2expl[errcode])
        elif errcode in dependent_errors:
            continue
        else:
            res.append("Explanation for errcode " + errcode + " is not available in our setup. Please refer to DNSViz "
                                                              "for details regarding this.")
    return res


def _pretty_print(instructions) -> str:
    res = ""
    for ind, instr in enumerate(instructions):
        if ind > 1:
            res += str(ind - 1) + ". " + instr + " "
        else:
            res += instr + " "
    return res
