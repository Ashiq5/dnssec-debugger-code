from config import INSTRUCTION_PATH, X3LD_KEY_DIR, ZONE_DIR, INPUT_GROK_PATH
from utils import (
    KEY2ALGO_MAPPING,
    keysize_required_algorithms,
    DEFAULT_ALGORITHM_TEXT,
    get_errcodes,
)
from utils.logging_utils import logger
from .execute_instructions import identify_zone_from_instr
from .util import (
    get_dnsviz_validation_cmd,
    run_dnsviz_validation,
    load_grok,
    find_errors_in_analysis,
    identify_zone_name,
    get_parent_zone,
    get_doe_params,
    populate_ds_map,
    populate_key_map,
    identify_auth_servers,
    get_topological_ordering,
    generate_resign_command,
    identify_erroneous_servers,
    identify_revoked_zone_sep_keys,
    identify_revoked_zone_keys,
    identify_non_revoked_zone_keys,
    identify_invalid_keys,
    find_out_dnskey_rrsig_key_tags,
    get_ttl_and_signature_validity,
    identify_delegated_names,
    identify_missing_algorithm,
)


def _dump_and_replace_instr_for_study(instructions):
    # rndc -k /data/bind1/rndc.key -p 953 reload
    # rndc -k /data/bind2/rndc.key -p 954 reload
    # replace the variables in sign_zone(cmd) function
    # replace variables: <key_dir>, <key_file>, <validity_interval_in_seconds>,
    # <zone_dir>, <signed_zone_file>, <unsigned_zone_file>
    f = open(INSTRUCTION_PATH, "w")
    parent_zone, zone = None, None
    for ind, instr in enumerate(instructions):
        if instr.startswith("Parent zone"):
            parent_zone = identify_zone_from_instr(instr, parent=True)
            zone = identify_zone_from_instr(instr, parent=False)
        if "BIND command" in instr:
            cmd_init = instr.split("BIND command for manual signing: ")[1][1:-1]
            cmd = cmd_init.replace("<key_dir>", X3LD_KEY_DIR + zone + "/")
            cmd = cmd.replace("<zone_dir/", ZONE_DIR)
            cmd = cmd.replace("unsigned_zone_file>", "db." + zone[:-1])
            cmd = cmd.replace("signed_zone_file>", "db." + zone[:-1] + ".signed")
            instr = instr.replace(cmd_init, cmd)
        if ind > 1:
            f.write(str(ind - 1) + ". " + instr + "\n")
    f.write(
        str(len(instructions) - 1)
        + ". Reload the bind9 server. BIND command for reloading: rndc -k /data/bind1/rndc.key -p 953 reload"
        + "\n"
    )
    # print(str(len(instructions)) + " Reload the bind9 server. BIND command: rndc -k /data/bind2/rndc.key -p 954 reload")


def get_high_level_instructions(
    zone_name: str = None, name: str = None, extra_qtypes: str = None
):
    try:
        # Step 1: Load validation data from file
        analysis = load_grok(PATH=INPUT_GROK_PATH)

        # Step 2: identify prevalent misconfigurations in analysis
        dom2err = find_errors_in_analysis(analysis)

        # Step 3: identify the name of the zone
        if not zone_name:
            zone_name = identify_zone_name(analysis)
        logger.logger.debug("In get instructions, zone: ", zone_name)
        if not zone_name:
            msg = "Can't find your zone from grok data. Please pass the developer your analyzed domain if this comes up."
            logger.logger.error(msg)
            return None, msg

        parent_zone_name = get_parent_zone(analysis, zone_name)
        logger.logger.debug("In get instructions, parent zone: ", parent_zone_name)
        parent_zone_doe_params = get_doe_params(analysis, parent_zone_name)
        if not parent_zone_name:
            msg = "Can't find your parent zone from grok data. Please pass the developer your analyzed domain if this comes up."
            logger.logger.error(msg)
            return None, msg
        if (
            not parent_zone_doe_params
        ):  # it's normal to find parent_zone_doe_params since it'll only have ds and dnskey queries
            parent_zone_doe_params = "NSEC/NSEC3", None

        # Step 4: focus on the errors that belong to the zone and it's descendants
        errcodes, ignored_errcodes = get_errcodes(zone_name, dom2err), set()
        for domain in dom2err:
            # adding ancestor errors to the ignored_errcodes
            # if len(domain) < len(zone_name):
            if not domain.endswith(zone_name):
                if dom2err[domain]:
                    for path in dom2err[domain]:
                        for err in dom2err[domain][path]:
                            ignored_errcodes.add(err["code"])

        # Step 5: populate metadata from analysis
        ds_map = populate_ds_map(analysis, zone_name)
        dnskey_map = populate_key_map(analysis, zone_name)
        # logger.logger.info("In get instructions, dnskey_map: ", dnskey_map)
        auth_servers = identify_auth_servers(analysis, zone_name)
        if not auth_servers:
            msg = "Can't find authoritative server(s) for your zone. Please pass the developer your analyzed domain if this comes up."
            logger.logger.error(msg)
            return None, msg
        doe_params = get_doe_params(
            analysis
        )  # trying to get doe_params for the queried domain
        if not doe_params:  # if not found, trying to get doe_params for the zone
            doe_params = get_doe_params(analysis, zone=zone_name)
        if not doe_params:
            doe_params = "NSEC/NSEC3", None

        # Step 6: pick the top priority error first which ensures dependent errors resolve their dependency first
        logger.logger.debug("In get instructions: present errors", errcodes)
        errcodes_to_resolve, msg = get_topological_ordering(errcodes, ignored_errcodes)
        if not errcodes_to_resolve:
            return None, msg
        # print(errcodes_to_resolve)
        # logger.logger.info("Errcodes in topological order is", ",".join(errcodes_to_resolve))

        # Step 7: generate manual signing command based on DoE parameters
        # common_instr = "Suggested commands are applicable if you are using BIND as your authoritative server software but should be easily extensible to other software as well. Replace the variables in angle brackets with values of your own environment. "
        # resign_command = generate_resign_command(zone_name, doe_params)
        # instructions_2d = [
        #     common_instr,
        #     "Parent zone -p " + parent_zone_name + " , invalid zone -c " + zone_name,
        # ]
        instructions_2d = []
        # todo: add the root cause at the start of the set of instructions. should be easily doable but will do it later

        for ind, top_errcode in enumerate(errcodes_to_resolve):
            instructions = []
            # Step 8: formulate instructions based on the topmost error
            if top_errcode == "DNSKEY_MISSING_FROM_SERVERS":
                erroneous_servers = set(identify_erroneous_servers(analysis))
                working_auth_servers = []
                working_auth_server_ips = set()
                not_working_auth_servers = set()
                not_working_auth_server_ips = set()
                for item in auth_servers:
                    for ip in item[1]:
                        if ip in erroneous_servers:
                            not_working_auth_servers.add(item[0])
                            not_working_auth_server_ips.add(ip)
                    if item[0] not in not_working_auth_servers:
                        working_auth_servers.append(item[0])
                        working_auth_server_ips.update(set(item[1]))
                working_auth_server_ips = list(working_auth_server_ips)
                not_working_auth_server_ips = list(not_working_auth_server_ips)
                if (
                    working_auth_servers
                ):  # case 1: a subset of auth server is working fine. pick any of the working one as a primary auth. example: dmfr
                    primary_auth_server = working_auth_servers[0]
                    instructions.append(
                        "Confirm Zone Transfer Permissions on the "
                        + primary_auth_server[:-1]
                        + " designated as the master."
                    )
                    instructions.append(
                        "Configure the erroneous servers to pull from the master."
                    )
                    instructions.append("Manually Trigger a Full Zone Transfer.")
                else:  # none of the auth servers are working fine.
                    # case 2: all have working dnskeys. pick anyone as a primary auth and resolve (example: expt)
                    primary_auth_server = auth_servers[0][0]  # picked first one
                    primary_auth_server_ips = auth_servers[0][1]
                    slave_auth_servers = []
                    for item in auth_servers[1:]:
                        slave_auth_servers.extend(item[1])
                    instructions.append(
                        "Confirm Zone Transfer Permissions on the "
                        + primary_auth_server[:-1]
                        + " designated as the master."
                    )
                    instructions.append(
                        "Configure the erroneous servers to pull from the master."
                    )
                    instructions.append("Manually Trigger a Full Zone Transfer.")
                    # case 3: none have working dnskeys. this case won't happen for this errcode since no "dnskeys" key will be there if none of the servers have any working dnskey
            elif top_errcode == "DNSKEY_REVOKED_DS":
                revoked_ksk_keys = identify_revoked_zone_sep_keys(dnskey_map)
                revoked_ksk_tags = [
                    str(dnskey_map[ksk_id][0]) for ksk_id in revoked_ksk_keys
                ]
                pre_revoked_ksk_tags = [
                    str(dnskey_map[ksk_id][4]) for ksk_id in revoked_ksk_keys
                ]
                ds_linked_ksk_tags = [
                    str(ds_map[ds_id][0])
                    for ds_id in ds_map
                    if str(ds_map[ds_id][0]) in revoked_ksk_tags
                ]
                if (
                    "NO_SEP" in errcodes
                ):  ## example: drd (only ksk is revoked), else: ddrd (other valid ksks exist)
                    for ksk_id in revoked_ksk_keys:
                        key_algorithm = KEY2ALGO_MAPPING[dnskey_map[ksk_id][1]]
                        if key_algorithm in keysize_required_algorithms:
                            keysize = dnskey_map[ksk_id][3]
                    digest_algorithm = set(
                        [
                            str(ds_map[ds_id][2])
                            for ds_id in ds_map
                            if str(ds_map[ds_id][0]) in revoked_ksk_tags
                        ]
                    )
                    if len(digest_algorithm) == 1:
                        digest_algorithm = list(digest_algorithm)[0]
                    else:
                        digest_algorithm = "2"
                    instructions.append("Generate a new KSK key pair.")
                    # instructions.append(
                    #     "Add the public key to the DNSKEY RRset. BIND instruction: add the `$INCLUDE <key_file>` line in the unsigned version of the zone file."
                    # )
                    instructions.append("Generate the corresponding DS record.")
                    instructions.append("Upload DS record in the parent zone.")
                # todo: ttl extraction not yet done
                instructions.append(
                    "Remove the DS record(s) linked to the revoked DNSKEY(s) (key_tag="
                    + ",".join(ds_linked_ksk_tags)
                    + ") from the parent zone. Wait at least one full TTL (the maximum TTL of the removed DS record(s)) for the removed DS record(s) to expire from the cache of any validator."
                )
                instructions.append(
                    "After the DS record(s) has expired from caches, remove the revoked DNSKEY(s) (key_tag="
                    + ",".join(revoked_ksk_tags)
                    + ") from your zone file. Key tags pre-revoke are (pre_revoke_key_tag="
                    + ",".join(pre_revoked_ksk_tags)
                    + ")"
                )
                instructions.append("Resign the zone.")
            elif top_errcode == "DNSKEY_REVOKED_RRSIG":
                revoked_zsk_keys = identify_revoked_zone_keys(dnskey_map)
                revoked_zsk_tags = [
                    str(dnskey_map[zsk_id][0]) for zsk_id in revoked_zsk_keys
                ]
                pre_revoked_zsk_tags = [
                    str(dnskey_map[zsk_id][4]) for zsk_id in revoked_zsk_keys
                ]
                non_revoked_zsk_tags = identify_non_revoked_zone_keys(dnskey_map)
                if (
                    "REVOKED_NOT_SIGNING" in errcodes or len(non_revoked_zsk_tags) == 0
                ):  # example: drr (only zsk is revoked), else: ddrr (other valid zsk exists)
                    for zsk_id in revoked_zsk_keys:
                        key_algorithm = KEY2ALGO_MAPPING[dnskey_map[zsk_id][1]]
                        if key_algorithm in keysize_required_algorithms:
                            keysize = dnskey_map[zsk_id][3]
                    instructions.append("Generate a new ZSK key pair.")
                    # instructions.append(
                    #     "Add the public key to the DNSKEY RRset. BIND instruction: add the `$INCLUDE <key_file>` line in the unsigned version of the zone file."
                    # )
                instructions.append(
                    "Remove the revoked DNSKEY(s) (key_tag="
                    + ",".join(revoked_zsk_tags)
                    + ") from your zone file. Key tags pre-revoke are (pre_revoke_key_tag="
                    + ",".join(pre_revoked_zsk_tags)
                    + ")"
                )
                instructions.append("Resign the zone.")
            elif (
                "DNSKEY_BAD_LENGTH" in top_errcode
                or "DNSKEY_ZERO_LENGTH" in top_errcode
            ):  # untested
                # case 2: you need to replace the invalid dnskey with a new key. you can make perhaps make things a bit more complex by checking whether other valid keys and delegation exists and then removing the invalid key will suffice.
                erroneous_keys = identify_invalid_keys(analysis)
                for key_id in erroneous_keys:
                    dsgen_cmd = None
                    key_algorithm = KEY2ALGO_MAPPING[dnskey_map[key_id][1]]
                    if key_algorithm in keysize_required_algorithms:
                        keysize = dnskey_map[key_id][3]
                    instructions.append(
                        "Generate a new key pair emulating the algorithm ("
                        + key_algorithm
                        + ") and flags ("
                        + str(dnskey_map[key_id][2])
                        + ") of the invalid key."
                    )
                    instructions.append("Add the public key to the DNSKEY RRset.")
                    if dsgen_cmd:
                        instructions.append("Generate the corresponding DS record.")
                instructions.append("Sign the zone using the newly generated keys.")
                instructions.append("Upload the DS record(s) in the parent zone.")
            elif top_errcode == "DIGEST_INVALID":
                mismatched_key_tags = []
                dsgen_cmds = []
                for key in ds_map:
                    if ds_map[key][3] == "INVALID_DIGEST":
                        mismatched_key_tags.append(str(ds_map[key][0]))
                        digest_algorithm = str(ds_map[key][2])
                        # dsgen_cmds.append("`cd <key_dir> && dnssec-dsfromkey -" + digest_algorithm + " <key_file_" + str(ds_map[key][0]) + ">`")
                        dsgen_cmds.append(
                            "`cd <key_dir> && dnssec-dsfromkey -"
                            + digest_algorithm
                            + " <key_file>`"
                        )
                instructions.append(
                    "You have DS record(s) with (key_tag="
                    + ",".join(mismatched_key_tags)
                    + ") where the digest value does not match with the corresponding DNSKEY(s). Remove these incorrect DS record(s)."
                )
                instructions.append(
                    "Generate the correct DS record(s) for the mismatched DNSKEYs with (key_tag="
                    + ",".join(mismatched_key_tags)
                    + ")."
                )
                instructions.append(
                    "Upload the correct DS record(s) to the parent zone."
                )
            elif top_errcode == "MISSING_SEP_FOR_ALG":
                # case 1: extraneous DS, 1 KSK, no ZSK
                # case 2: extraneous DS, 1 KSK, 1 ZSK
                # case 3: extraneous DS, >1 KSKs, example: msa
                # case 4: ds exists but no DNSKEY, example: nodnskey
                # case 5: ds exists, DNSKEY exists but no RRSIG for KSK DNSKEY, example: nosep, wnc (shows that for zsk, this error does not come), TODO: devise one for multiple KSKs with one missing RRSIG (no error) and all missing RRSIG (yes, same as 1 though)
                is_solution_found = False
                extraneous_ds_tags = []
                # revoked_ds_tags = []
                for key in ds_map:
                    if ds_map[key][3] == "INDETERMINATE_NO_DNSKEY":
                        extraneous_ds_tags.append(str(ds_map[key][0]))
                    # elif ds_map[key][3] == 'INDETERMINATE_MATCH_PRE_REVOKE':
                    #     revoked_ds_tags.append(str(ds_map[key][0]))
                is_ksk_present = False
                for key in dnskey_map:
                    if dnskey_map[key][2] == 257:
                        is_ksk_present = True
                        break
                if extraneous_ds_tags:
                    is_solution_found = True
                    if not is_ksk_present:
                        keygen_cmd, dsgen_cmd = None, None
                        for key in dnskey_map:
                            key_algorithm = None
                            if dnskey_map[key][2] == 256:
                                key_algorithm = KEY2ALGO_MAPPING[dnskey_map[key][1]]
                            if key_algorithm:
                                if key_algorithm in keysize_required_algorithms:
                                    keysize = dnskey_map[key][3]
                                    keygen_cmd = (
                                        "`cd <key_dir> && dnssec-keygen -f KSK -a "
                                        + key_algorithm
                                        + " -b "
                                        + str(keysize)
                                        + " -n ZONE "
                                        + zone_name
                                        + "`"
                                    )
                                else:
                                    keygen_cmd = (
                                        "`cd <key_dir> && dnssec-keygen -f KSK -a "
                                        + key_algorithm
                                        + " -n ZONE "
                                        + zone_name
                                        + "`"
                                    )
                        if not keygen_cmd:
                            # only happens when there are no ZSKs as well.
                            instructions.append("Generate a new ZSK key pair.")
                        instructions.append("Generate a new KSK key pair.")
                        # instructions.append(
                        #     "Add the public key to the DNSKEY RRset. BIND instruction: add the `$INCLUDE <key_file>` line in the unsigned version of the zone file."
                        # )
                        digest_algorithm = set(
                            [str(ds_map[ds_id][2]) for ds_id in ds_map]
                        )
                        if len(digest_algorithm) == 1:
                            digest_algorithm = list(digest_algorithm)[0]
                        else:
                            digest_algorithm = "2"
                        instructions.append("Generate the corresponding DS record.")
                        instructions.append("Upload DS record in the parent zone.")
                        instructions.append("Resign the zone.")
                    instructions.append(
                        "You have DS record(s) with (key_tag="
                        + ",".join(extraneous_ds_tags)
                        + ") where there are no corresponding DNSKEY(s). Remove these extraneous DS record(s) from the parent zone."
                    )
                dnskey_rrsig_key_tags = find_out_dnskey_rrsig_key_tags(
                    analysis, zone_name
                )
                absent_ksk_rrsig_tags = []
                for key in dnskey_map:
                    if (
                        dnskey_map[key][2] == 257
                        and dnskey_map[key][0] not in dnskey_rrsig_key_tags
                    ):
                        absent_ksk_rrsig_tags.append(str(dnskey_map[key][0]))
                if absent_ksk_rrsig_tags:
                    is_solution_found = True
                    instructions.append(
                        "You have key-signing DNSKEY record(s) with (key_tag="
                        + ",".join(absent_ksk_rrsig_tags)
                        + ") for which there are no RRSIG(s). Resigning the zone should resolve the issue."
                    )
                if not is_solution_found:
                    msg = "There must be something else going wrong. Please pass the developer your analyzed domain if this comes up."
                    logger.logger.error(msg)
                    return None, msg
                # if len(extraneous_ds_tags) == len(ds_map):  # applicable for case 3 only
                #     instructions.append("Note that this will correctly disable DNSSEC for your zone.")
            elif top_errcode == "MISSING_RRSIG":  # untested
                if not dnskey_map:
                    msg = "This edge case where no DNSKEY is present but zone is not insecure should never occur. Please pass the developer your analyzed domain if this comes up."
                    # msg = (
                    #     "No DNSKEY is present but there are error(s) which means the zone is not insecure. So, it has DS records; which means the error should be MISSING_SEP_FOR_ALG and resolving that should automatically resolve this and code should never reach here. Please contact the developer with the domain if this edge case comes up."
                    # )
                    logger.logger.error(msg)
                    return None, msg
                instructions.append("Resign the zone.")
            elif top_errcode == "MISSING_RRSIG_FOR_ALG_DNSKEY":
                # case 1: zsk with a unique algo did not sign the dnskey rrset; example: mra
                # case 2: ksk with a unique algo did not sign the other rrsets; example: mka
                missing_algos = identify_missing_algorithm(dom2err)
                for algo in missing_algos:
                    instructions.append(
                        "You have one or more DNSKEY(s) with algorithm "
                        + algo
                        + " but no RRSIG with this algorithm is present for these RRSets: "
                        + ",".join(missing_algos[algo])
                    )
                instructions.append(
                    "Note that if you have DNSKEYs covering multiple algorithms, at least one key from each algorithm needs to sign all the RRSet (including the DNSKEY RRSet) in your zone."
                )
                resign_command = generate_resign_command(
                    zone_name, doe_params, ignore_ksk=True
                )
                instructions.append("Resign the zone.")
            elif top_errcode == "SIGNATURE_INVALID":
                instructions.append("Resign the zone.")
            elif top_errcode == "SIGNER_NOT_ZONE":
                instructions.append("Resign the zone.")
            elif (
                top_errcode == "RRSIG_LABELS_EXCEED_RRSET_OWNER_LABELS"
            ):  # untested: does not appear with dnsviz CLI
                instructions.append("Resign the zone.")
            elif "RRSIG_BAD_LENGTH" in top_errcode:  # untested
                instructions.append("Resign the zone.")
            elif top_errcode == "INCEPTION_IN_FUTURE":
                instructions.append("Resign the zone.")
            elif top_errcode == "EXPIRATION_IN_PAST":
                instructions.append("Resign the zone.")
            elif top_errcode == "TTL_BEYOND_EXPIRATION":
                record_ttl, rrsig_ttl, rrsig_validity = get_ttl_and_signature_validity(
                    analysis
                )
                if not record_ttl or not rrsig_ttl or not rrsig_validity:
                    instructions.append("Resign the zone.")
                resign_command = generate_resign_command(
                    zone_name, doe_params, expiration=True
                )
                if record_ttl and rrsig_ttl and rrsig_validity:
                    instructions.append(
                        "Your record TTL is "
                        + str(record_ttl)
                        + " seconds. Your signature TTL is "
                        + str(rrsig_ttl)
                        + " seconds and your signature validity interval is "
                        + str(rrsig_validity)
                        + " seconds."
                    )
                    if rrsig_ttl <= 300:  # untested
                        instructions.append(
                            "Resign the zone with a higher signature validity since your signature TTL is quite short."
                        )
                    elif rrsig_ttl >= rrsig_validity / 4:
                        instructions.append(
                            "Your signature TTL is quite large compared to your signature validity. We recommend reducing your zone/record TTL and make it at max 1/4th of your signature validity and resign the zone."
                        )
                    else:  # rrsig_ttl < rrsig_validity/4, untested
                        instructions.append(
                            "We recommend reducing your zone/record TTL to 300s and resign the zone."
                        )
            elif (
                "ORIGINAL_TTL_EXCEEDED" in top_errcode
            ):  # untested: ORIGINAL_TTL_EXCEEDED_RRSIG
                instructions.append("Resign the zone.")
            elif top_errcode in {
                "NO_NSEC_MATCHING_SNAME",
                "LAST_NSEC_NEXT_NOT_ZONE",
            }:  # untested: LAST_NSEC_NEXT_NOT_ZONE*
                instructions.append(
                    "Something is wrong with your NSEC configuration. Resigning the zone should resolve the issue."
                )
            elif top_errcode == "OPT_OUT_FLAG_NOT_SET":  # untested
                if not doe_params or doe_params[0] != "NSEC3":
                    msg = "This edge case should never occur as the error code indicates the domain owner used NSEC3 record(s) to prove denial of existence. Please pass the developer your analyzed domain if this comes up."
                    # msg = (
                    #     "It can't be. It needs to be NSEC3 records for sure. Code should never reach here. Please contact the developer with the grok file if this comes up."
                    # )
                    logger.logger.error(msg)
                    return None, msg
                # setting the resign_command explicitly to make sure the -A flag is set in case the previous flag was 0
                resign_command = generate_resign_command(
                    zone_name, doe_params, optout_flag=True
                )
                instructions.append(
                    "Something is wrong with your NSEC3 configuration. Resigning the zone should resolve the issue."
                )
            elif top_errcode in {
                "NO_NSEC3_MATCHING_SNAME",
                "NO_CLOSEST_ENCLOSER",
                "INCONSISTENT_NXDOMAIN_ANCESTOR",
                "NEXT_CLOSEST_ENCLOSER_NOT_COVERED",
                "INVALID_NSEC3_HASH",
                "INVALID_NSEC3_OWNER_NAME",
            }:  # untested: NO_NSEC3_MATCHING_SNAME*, INCONSISTENT_NXDOMAIN_ANCESTOR, NEXT_CLOSEST_ENCLOSER_NOT_COVERED, INVALID_NSEC3_OWNER_NAME
                instructions.append(
                    "Something is wrong with your NSEC3 configuration. Resigning the zone should resolve the issue."
                )
            elif (
                top_errcode == "NONZERO_NSEC3_ITERATION_COUNT"
            ):  # untested*: does not appear with dnsviz CLI
                instructions.append(
                    "NSEC3 iteration count needs to be 0 to prevent computational burden on validating resolvers. Resigning the zone by explicitly setting the iteration count to 0 should resolve the issue."
                )
            elif top_errcode == "UNSUPPORTED_NSEC3_ALGORITHM":  # untested*
                instructions.append(
                    "Only one NSEC3 algorithm type is supported (algorithm value should be 1). Resigning the zone should resolve the issue."
                )
            elif top_errcode == "REFERRAL_WITH_DS":
                delegated_names = identify_delegated_names(dom2err, "REFERRAL_WITH_DS")
                resign_command = generate_resign_command(
                    parent_zone_name, parent_zone_doe_params
                )
                instructions.append(
                    "Although the following delegated zone(s):"
                    + ",".join(delegated_names)
                    + " are unsigned, the DS bit is set on their "
                    + parent_zone_doe_params[0]
                    + " record of the parent zone ("
                    + parent_zone_name
                    + "). Please ask the parent zone owner to either unset the DS bit from the "
                    + parent_zone_doe_params[0]
                    + " record(s) of the following owner names:"
                    + ",".join(delegated_names)
                    + " in the parent zone and regenerate the RRSIG of these "
                    + parent_zone_doe_params[0]
                    + " record(s)."
                )
                instructions.append(
                    "Or, resign the parent zone which should typically resolve the issue automatically."
                )
            elif top_errcode == "REFERRAL_WITH_SOA":
                delegated_names = identify_delegated_names(dom2err, "REFERRAL_WITH_SOA")
                resign_command = generate_resign_command(
                    parent_zone_name, parent_zone_doe_params
                )
                instructions.append(
                    "The following delegated zone(s):"
                    + ",".join(delegated_names)
                    + " have the SOA bit turned on in their "
                    + parent_zone_doe_params[0]
                    + " record of the parent zone ("
                    + parent_zone_name
                    + "). Please ask the parent zone owner to either unset the SOA bit from the "
                    + parent_zone_doe_params[0]
                    + " record(s) of the following owner names:"
                    + ",".join(delegated_names)
                    + " and regenerate the RRSIG of these "
                    + parent_zone_doe_params[0]
                    + " record(s)."
                )
                instructions.append(
                    "Or, resign the parent zone which should typically resolve the issue automatically."
                )
            elif top_errcode == "REFERRAL_WITHOUT_NS":
                delegated_names = identify_delegated_names(
                    dom2err, "REFERRAL_WITHOUT_NS"
                )
                resign_command = generate_resign_command(
                    parent_zone_name, parent_zone_doe_params
                )
                instructions.append(
                    "The following delegated zone(s):"
                    + ",".join(delegated_names)
                    + " have the NS bit unset in their "
                    + parent_zone_doe_params[0]
                    + " record of the parent zone ("
                    + parent_zone_name
                    + "). Please ask the parent zone owner to either set the NS bit at the "
                    + parent_zone_doe_params[0]
                    + " record(s) of the following owner names:"
                    + ",".join(delegated_names)
                    + " in the parent zone and regenerate the RRSIG of these "
                    + parent_zone_doe_params[0]
                    + " record(s)."
                )
                instructions.append(
                    "Or, resign the parent zone which should typically resolve the issue automatically."
                )
            elif top_errcode in {
                "SNAME_COVERED",
                "SNAME_NOT_COVERED",
                "EXISTING_NAME_COVERED",
                "WILDCARD_COVERED",
                "WILDCARD_NOT_COVERED",
                "EXISTING_TYPE_NOT_IN_BITMAP",
                "STYPE_IN_BITMAP",
            }:  # untested: SNAME_COVERED, EXISTING_NAME_COVERED*, WILDCARD_COVERED, WILDCARD_NOT_COVERED
                instructions.append(
                    "Something is wrong with your "
                    + doe_params[0]
                    + " configuration. Resigning the zone should resolve the issue."
                )
            elif top_errcode in {
                "MISSING_NSEC_FOR_NODATA",
                "MISSING_NSEC_FOR_NXDOMAIN",
                "MISSING_NSEC_FOR_WILDCARD",
            }:  # should automatically find the grand-children node but need to test
                instructions.append(
                    "Something is wrong with your "
                    + doe_params[0]
                    + " configuration. Resigning the zone should resolve the issue."
                )
            # if len(sys.argv) > 1:
            #     instructions.append(
            #         "Run dnsviz valiation again to see whether the issue got resolved. Shell command: `"
            #         + dnsviz_cmd
            #         + "`"
            #     )
            instructions_2d.append(instructions)
            # print(instructions)

        # since wo zrep instructions actually do not remove errors, there might be duplicate
        # instructions; so, we need to filter them out
        # example scenario: imagine a domain having two errcodes: "missing_nsec_for_nodata", "existing_type_not_in_bitmap"
        unique_instr_wo_zrep = []
        seen = set()
        for lst in instructions_2d:
            key = tuple(lst)  # make it hashable
            if key not in seen:
                seen.add(key)
                unique_instr_wo_zrep.append(lst)  # keep original list
        return unique_instr_wo_zrep, ""
    except Exception as e:
        import traceback

        traceback.print_exc()
