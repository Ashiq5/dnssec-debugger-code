import argparse
import json
import os
import subprocess
import sys
import traceback

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from publicsuffixlist import PublicSuffixList

from DFixer import identify_meta_parameters
from domaingenerator import NamedConf
from domaingenerator import SigningParameters
from grokreader import sort_as_nsec

from src.DFixer.util import (
    find_errors_in_analysis,
    identify_zone_name,
    update_server,
    get_dnsviz_validation_cmd,
    run_dnsviz_validation,
)
from grokreader import GrokData
from utils import DNSSECRelatedErrors

from DFixer import _pretty_print
from ZReplicator import (
    delete_old_keys,
    get_errcodes,
    make_one_new_case,
    update_root,
    prepare_root,
)
from DFixer import get_high_level_instructions, get_instructions, get_error_explanation
from DFixer import execute_instructions


# Import new utilities
from utils.logging_utils import logger
from config import *


class Result:
    def __init__(self, filename):
        self.val = dict()
        self.filename = filename

    def add(self, key, val):
        self.val[key] = val

    def to_json(self):
        return json.dumps(self.val)

    def to_dict(self):
        return self.val

    def return_value(self):
        return self.to_json()

    def return_and_write(self):
        self.write_to_file()
        return self.return_value()

    def get(self, key):
        return self.val.get(key)

    def write_to_file(self):
        if self.filename == "stdout":
            print(self.to_json())
        else:
            try:
                with open(self.filename, "a") as f:
                    f.write(self.to_json() + "\n")
            except Exception as e:
                logger.logger.error(
                    f"Failed to write to output file {self.filename}: {e}"
                )
                print(self.to_json())  # Fallback to stdout


output_file_name = "stdout"
result = Result(filename=output_file_name)


def process_a_grok_file(domain=None, input_line=None):
    psl = PublicSuffixList()

    # Create logs directory
    Path("logs").mkdir(exist_ok=True)

    # Get the preliminary grok analysis if not available
    if domain:
        logger.logger.info(f"Retrieving grok info for fqdn {domain}")
        grok_resolve_command = f"dnsviz probe -A {domain} -a . | dnsviz grok"
        logger.logger.info(f"using grok command : {grok_resolve_command}")
        grok_result = subprocess.run(
            grok_resolve_command, shell=True, capture_output=True
        )
        logger.logger.debug(grok_result)
        input_line = json.dumps([-1, [200, json.loads(grok_result.stdout)]])

    # Load the input
    try:
        line = json.loads(input_line)
    except Exception as e:
        result.add("exception", e.__str__())
        return result.return_and_write()

    id_, analysis = line[0], line[1][1]

    grok_data = GrokData(input_line, homemade_measurement=True)

    # We will need the data in a specific file later
    # This is the grok data that we are currently handling
    json.dump(analysis, open(INPUT_GROK_PATH, "w"), indent=4)

    result.add("id", id_)

    if line[1][0] not in ["200", 200]:
        result.add("status", line[1][0])
        return result.return_and_write()

    try:
        dom2err = find_errors_in_analysis(analysis, psl=psl)
        # The analysis stops here as there is no DNSSEC error
        # This part should be unnecessary
        # if not dom2err:
        #     logger.logger.error("Cannot parse the grok output to find errors")
        #     return result.return_and_write()

        zone_name = identify_zone_name(analysis)
        # The analysis stops here as we can not identify the zone name
        if not zone_name:
            logger.logger.error("Failed to identify zone name")
            logger.logger.error(zone_name)
            return result.return_and_write()
        result.add("zone_name", zone_name)

        # Compute the error codes that are on the input file
        intended_errcodes = get_errcodes(zone_name, dom2err)
        result.add("intended_errcodes", list(intended_errcodes))

        explanations = get_error_explanation(intended_errcodes)
        result.add("explanations", explanations)

        # If there is no errcode related to dnssec information (e.g. network issue) stop here
        if not [i for i in intended_errcodes if i in DNSSECRelatedErrors]:
            logger.logger.error("Cannot find paper-related DNSSEC errors")
            return result.return_and_write()

        if APPLY_FIX:
            logger.logger.info("Applying fixes")
            # Applying fix
            logger.logger.info("Get high level instructions")
            instructions_2d, msg = get_high_level_instructions(zone_name)
            if not instructions_2d:
                result.add("message", msg)
                return result.return_and_write()
            result.add(
                "instructions_wo_zrep",
                instructions_2d if instructions_2d is not None else [],
            )
            result.add("fix_iterations_wo_zrep", len(instructions_2d))

        # return result.return_and_write()
        # This is where ZReplicator starts
        # First, we create a base zone
        root_domain_class, root_zone_file = prepare_root()
        primary_zone, secondary_zone = [root_domain_class], [root_domain_class]

        # Remove old keys
        delete_old_keys()

        # Identifying meta parameters of the zone to emulate
        params = identify_meta_parameters(id_, analysis, psl=psl, grok_data=grok_data)
        logger.logger.debug(f"Params: {params}")

        if (
            params == "Exception!!!Probably Delegated"
            or params == "Exception!!!Unsigned Parent Zone"
            or params == "Exception!!!No Parent Zone"
        ):
            logger.logger.error(params)
            result.add("params", params)

        if params == "Exception!!!Probably Delegated":
            result.add(
                "zrep_failure",
                "At the moment, ZReplicator does not handle CNAME or DNAME delegations, which is probably the case here. Please pass the developer your analyzed domain if this is not the case.",
            )
            return result.return_and_write()
        elif params == "Exception!!!Unsigned Parent Zone":
            result.add(
                "zrep_failure",
                "At the moment, ZReplicator does not reproduce zones whose parent zone is unsigned, which is probably the case here. Please pass the developer your analyzed domain if this is not the case.",
            )
            return result.return_and_write()
        elif params == "Exception!!!No Parent Zone":
            result.add(
                "zrep_failure",
                "At the moment, ZReplicator does not reproduce zones with no parent zone, which is probably the case here. Please pass the developer your analyzed domain if this is not the case.",
            )
            return result.return_and_write()

        error_list = [err.error_type for err in params[2].errors]

        logger.logger.debug(f"error_list: {error_list}")
        logger.logger.debug(
            f"parent_dnskey_list: {[key.__dict__ for key in params[3].list]}"
        )
        logger.logger.debug(
            f"children_dnskey_list: {[key.__dict__ for key in params[4].list],}"
        )
        logger.logger.debug(f"parent_nsec_option: {params[5].__dict__}")
        logger.logger.debug(f"children_nsec_option: {params[6].__dict__}")

        signing_parameters = SigningParameters(grok_data.get_signing_information())
        case = params[0]
        (
            _,
            _,
            _,
            parent_domain_class,
            child_domain_class,
            unsigned_child_domain_class,
            grand_children_use_case,
            _,
        ) = make_one_new_case(
            case_name=case,
            parent=params[1],
            dnssec_errors=params[2],
            parent_key_list=params[3],
            children_key_list=params[4],
            parent_nsec_option=params[5],
            children_nsec_option=params[6],
            parent_ns=params[7],
            child_ns=params[8],
            inception=params[9],
            expiration=params[10],
            is_children_signed=params[11],
            wildcard_subdomain=params[12],
            nb_subdomains_children=params[13],
            parent_specific_parameters=params[14],
            children_specific_parameters=params[15],
            signing_parameters=signing_parameters,
            ds_map=params[18],
        )

        # Prepare Zonefile
        update_root(root_zone_file, parent_domain_class)
        primary_zone.extend(
            [parent_domain_class, child_domain_class, grand_children_use_case]
        )
        if unsigned_child_domain_class:
            primary_zone.append(unsigned_child_domain_class)
        NamedConf([z.fqdn for z in primary_zone], Path(SERVER_ZONE_DIR)).write(
            Path(ZONE_CONF_FILE), "master"
        )
        if HAVE_SECONDARY_ZONE:
            secondary_zone.extend(
                [parent_domain_class, child_domain_class, grand_children_use_case]
            )
            if unsigned_child_domain_class:
                secondary_zone.append(unsigned_child_domain_class)
            NamedConf(
                [z.fqdn for z in secondary_zone], Path(SERVER_ZONE_DIR_SECOND_NS)
            ).write(Path(ZONE_CONF_FILE_SECONDARY_NS), "master")

        logger.logger.info("Reloading Bind")
        update_server(case)

        # trying each query domain to find out each error
        qdomains = params[16]
        logger.logger.debug("Reloading Bind")
        generated_errcodes = set()

        for qdomain in qdomains:
            query_domain = qdomain
            extra_qtypes = params[17]
            if extra_qtypes:
                extra_args = "-R " + extra_qtypes
            else:
                extra_args = ""
            cmd = get_dnsviz_validation_cmd(query_domain, extra_args)
            run_dnsviz_validation(cmd)
            temp_analysis = json.load(open(GENERATED_GROK_PATH))

            dom2err = find_errors_in_analysis(temp_analysis, psl=psl)
            logger.logger.debug(f"d2e : {dom2err}")
            zone_name = identify_zone_name(temp_analysis)
            logger.logger.debug(f"In populating generated errcodes: zone {zone_name}")
            if not zone_name:
                continue

            generated_errcodes.update(get_errcodes(zone_name, dom2err))
        result.add("generated_errcodes", list(generated_errcodes))

        logger.logger.info(f'Generated errcodes : {result.get("generated_errcodes")}')
        logger.logger.info(f'Intended errcodes  : {result.get("intended_errcodes")}')
        logger.logger.info(
            f'Missing Errorcodes : { set(result.val["intended_errcodes"]) - set(result.val["generated_errcodes"])}'
        )

        # Start of DFixer on replicated zones
        if APPLY_FIX:
            logger.logger.info("Applying fixes")
            # Applying fix
            fix_transition_errcodes = []
            after_fix_errcodes = set([i for i in generated_errcodes])
            prev = set([i for i in generated_errcodes])
            prev.update({"RANDOM"})

            def is_fixed_or_stuck():
                # resolved
                if len(after_fix_errcodes) == 0:
                    return True
                # might be stuck bcs more errors getting appended
                if len(after_fix_errcodes) > len(prev):
                    return True
                # might be stuck bcs they are equal
                # if after_fix_errcodes == prev:
                #     return True
                # in case, make sure it doesn't get stuck
                if iteration_fix > 10:
                    return True
                return False

            iteration_fix = 0
            while not is_fixed_or_stuck():
                prev = after_fix_errcodes
                log_fix = []
                for qdomain in sort_as_nsec(list(qdomains)):
                    res = dict()

                    query_domain = qdomain
                    extra_qtypes = params[17]
                    if extra_qtypes:
                        extra_args = "-R " + extra_qtypes
                    else:
                        extra_args = ""
                    cmd = get_dnsviz_validation_cmd(query_domain, extra_args)
                    run_dnsviz_validation(cmd)
                    temp_analysis = json.load(open(GENERATED_GROK_PATH))
                    zone_name = identify_zone_name(temp_analysis)
                    logger.logger.info(f"Start of applying fix {zone_name}")
                    after_fix_errcodes = []
                    instructions = get_instructions(zone_name)
                    if instructions:
                        logger.logger.debug(_pretty_print(instructions))
                        try:
                            execute_instructions(instructions)
                        except Exception as e:
                            logger.logger.error(f"Exception !!! : {e.__str__()}")

                        update_server(case)
                        cmd = get_dnsviz_validation_cmd(query_domain, extra_args)
                        run_dnsviz_validation(cmd)
                        temp_analysis = json.load(open(GENERATED_GROK_PATH))
                        dom2err = find_errors_in_analysis(temp_analysis, psl=psl)
                        zone_name = identify_zone_name(temp_analysis)

                        logger.logger.info(f"After applying fix {zone_name}")
                        if not zone_name:
                            continue
                        temp = get_errcodes(zone_name, dom2err)

                        # fix_transition_errcodes.append(list(temp))
                        after_fix_errcodes = temp
                    res["domain"] = qdomain
                    res["instructions"] = (
                        instructions if instructions is not None else []
                    )
                    log_fix.append(res)

                fix_transition_errcodes.append(
                    {
                        "errors_before_fix": list(prev),
                        "errors_after_fix": list(after_fix_errcodes),
                        "fixes": log_fix,
                    }
                )
                logger.logger.info(f"Error before the fix : {generated_errcodes}")
                logger.logger.info(
                    f"Errors after current DFixer itteration #{iteration_fix} :  {after_fix_errcodes} "
                )

                iteration_fix += 1

            result.add("fix_transition_errcodes", list(fix_transition_errcodes))
            result.add("fix_iterations", iteration_fix)
            # result.add("after_fix_errcodes", list(after_fix_errcodes))

        return result.return_and_write()

    except Exception as e:
        logger.logger.error("\n\nException!!!")
        traceback.print_exc()
        result.add("exception", str(e))
        return result.return_and_write()


def main(domain=None, ids_=None):
    try:
        if ids_ and isinstance(ids_, list):
            ids = args.ids.split(",")
            finput = open(BATCH_GROK_PATH)
            for line in finput:
                if json.loads(line)[0] in ids:
                    return process_a_grok_file(None, line)
        elif domain:
            logger.logger.info("Starting DFixer + ZRep analysis")
            return process_a_grok_file(domain, None)
        else:
            msg = "No valid domain is passed"
            logger.logger.error(msg)
            result.add("exception", msg)
            return result.return_and_write()
    except Exception as e:
        logger.logger.error(f"Fatal error in main: {e}")
        logger.logger.error(traceback.format_exc())
        result.add("exception", str(e))
        return result.return_and_write()

    logger.logger.info("Analysis complete")


if __name__ == "__main__":
    main(domain="dnssec-failed.org")
