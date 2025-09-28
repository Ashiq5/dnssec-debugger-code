import os
import subprocess
from datetime import datetime, timezone

from config import X3LD_KEY_DIR, ZONE_DIR, ZONE_DIR_SECOND_NS
from utils.logging_utils import logger


def identify_zone_from_keygen(cmd):
    zone = cmd.split("-n ZONE ")[1].split()[0]
    return zone


def identify_zone_from_signzone(cmd):
    zone = cmd.split("-o ")[1].split()[0]
    return zone


def identify_zone_from_instr(instr, parent=False):
    if parent:
        flag = "-p "
    else:
        flag = "-c "
    zone = instr.split(flag)[1].split()[0]
    return zone


def identify_key_tags_from_instr(instr):
    key_tags = instr.split("key_tag=")[1].split(")")[0]
    return key_tags.split(",")


def identify_pre_revoke_key_tags_from_instr(instr):
    key_tags = instr.split("pre_revoke_key_tag=")[1].split(")")[0]
    return key_tags.split(",")


def generate_key_pair(cmd):
    zone = identify_zone_from_keygen(cmd)
    cmd = cmd.replace("<key_dir>", X3LD_KEY_DIR + zone + "/")

    logger.logger.debug("Generating Key Pair with", cmd)
    result = subprocess.run(cmd, shell=True, capture_output=True)
    if result.stdout:
        return result.stdout.decode().strip()


def generate_ds_record(zone, cmd, key_file):
    cmd = cmd.replace("<key_dir>", X3LD_KEY_DIR + zone + "/")
    cmd = cmd.replace("<key_file>", key_file + ".key")
    logger.logger.debug("Generating DS record with", cmd)
    result = subprocess.run(cmd, shell=True, capture_output=True)
    if result.stdout:
        return result.stdout.decode().strip()


def upload_ds_record(parent_zone, ds_record):
    logger.logger.debug("Uploading DS record to parent zone", ds_record)
    f = open(os.path.join(ZONE_DIR, "db." + parent_zone[:-1]), "a")
    f.write("\n" + ds_record + "\n")
    f.close()


def remove_from_parent_zone(parent_zone, key_tag):
    line_no_to_remove = None
    unsigned_parent_zone_file = ZONE_DIR + "db." + parent_zone[:-1]
    f = open(unsigned_parent_zone_file)
    lines = f.readlines()
    f.close()
    for ind, line in enumerate(lines):
        if "DS" in line and key_tag in line:
            line_no_to_remove = ind
            break
    logger.logger.debug("Removing DS record from parent zone", lines[line_no_to_remove])
    if line_no_to_remove:
        lines = lines[:line_no_to_remove] + lines[line_no_to_remove + 1 :]
        f = open(unsigned_parent_zone_file, "w")
        f.write("".join(lines))
        f.close()


def set_deletion_date_for_dnskey(zone, key_tag):
    key_dir = X3LD_KEY_DIR + zone + "/"
    deletion_time = (
        datetime.now(timezone.utc).astimezone().strftime("%Y%m%d%H%M") + "00"
    )  # to make sure deletion date is in the past
    key_files = os.listdir(key_dir)
    for key_file in key_files:
        if key_tag in key_file and ".key" in key_file:
            result = subprocess.run(
                "dnssec-settime -D " + deletion_time + " " + key_dir + key_file,
                shell=True,
                capture_output=True,
            )
            logger.logger.debug("Setting deletion date of " + key_file)
            stdout, stderr = result.stdout.decode(), result.stderr.decode()
            if stderr:
                if "warning" not in stderr:
                    raise Exception(
                        "Could not set the deletion time of the revoked key with tag "
                        + key_tag
                        + " because of error: "
                        + stderr
                    )
            break


def execute_signzone_cmd(cmd, retry):
    result = subprocess.run(cmd, shell=True, capture_output=True)
    stdout = result.stdout.decode().split("\n") + result.stderr.decode().split("\n")
    for line in stdout:
        if "Zone fully signed:" in line:
            return True, None
        if (
            "DNSSEC completeness test failed." in line
            or "No non-KSK DNSKEY found;" in line
            or "No self-signed KSK DNSKEY found" in line
        ):
            # adding ignore_ksk flag and trying again
            retry = retry.replace("-o ", "-z -o ")
            print("Retrying signzone with command ", retry)
            if sign_zone(retry):
                return True, None
    return False, stdout


def sign_parent_zone(parent_zone):
    cmd = (
        "cd <key_dir> && dnssec-signzone -N INCREMENT -S -o "
        + parent_zone
        + " -t -f <zone_dir/signed_zone_file> <zone_dir/unsigned_zone_file>"
    )
    cmd = cmd.replace("<key_dir>", X3LD_KEY_DIR + parent_zone + "/")
    cmd = cmd.replace("<zone_dir/", ZONE_DIR)
    cmd = cmd.replace("unsigned_zone_file>", "db." + parent_zone[:-1])
    cmd = cmd.replace("signed_zone_file>", "db." + parent_zone[:-1] + ".signed")
    retry = cmd
    logger.logger.debug("Signing the parent zone with", cmd)
    is_executed, stdout = execute_signzone_cmd(cmd, retry)
    if not is_executed:
        raise Exception("Parent zone signing resulted in failure: " + "\n".join(stdout))
    return True


def sign_zone(cmd):
    zone = identify_zone_from_signzone(cmd)
    cmd = cmd.replace("<key_dir>", X3LD_KEY_DIR + zone + "/")
    cmd = cmd.replace("<zone_dir/", ZONE_DIR)
    cmd = cmd.replace("unsigned_zone_file>", "db." + zone[:-1])
    cmd = cmd.replace("signed_zone_file>", "db." + zone[:-1] + ".signed")
    retry = cmd
    logger.logger.debug("Signing the zone with", cmd)
    is_executed, stdout = execute_signzone_cmd(cmd, retry)
    if not is_executed:
        raise Exception("Zone signing resulted in failure: " + "\n".join(stdout))
    return True


def sign_zone_with_expiration(cmd, validity):
    zone = identify_zone_from_signzone(cmd)
    cmd = cmd.replace("<key_dir>", X3LD_KEY_DIR + zone + "/")
    cmd = cmd.replace("<zone_dir/", ZONE_DIR)
    cmd = cmd.replace("<validity_interval_in_seconds>", str(validity))
    cmd = cmd.replace("unsigned_zone_file>", "db." + zone[:-1])
    cmd = cmd.replace("signed_zone_file>", "db." + zone[:-1] + ".signed")
    retry = cmd
    logger.logger.debug("Signing the zone with", cmd)
    is_executed, stdout = execute_signzone_cmd(cmd, retry)
    if not is_executed:
        raise Exception("Zone signing resulted in failure: " + "\n".join(stdout))
    return True


def extract_ttl_and_validity(instr):
    record_ttl = instr.split("Your record TTL is ")[1].split(
        " seconds. Your signature TTL is"
    )[0]
    rrsig_ttl = instr.split("Your signature TTL is ")[1].split(
        " seconds and your signature validity interval is "
    )[0]
    validity = instr.split(" seconds and your signature validity interval is ")[
        1
    ].split(" seconds")[0]
    return int(float(record_ttl)), int(float(rrsig_ttl)), int(float(validity))


def reduce_zone_ttl_indi_format(zone, old_record_ttl, old_rrsig_ttl, new_ttl):
    unsigned_zone_fn = ZONE_DIR + "db." + zone[:-1]
    f = open(unsigned_zone_fn)
    lines = f.readlines()
    f.close()
    new_lines = []
    for ind, line in enumerate(lines):
        temp = line
        if str(old_record_ttl) + " IN " in line:
            temp = line.replace(str(old_record_ttl) + " IN", str(new_ttl) + " IN ")
            logger.logger.debug(
                "Updating record TTL from ", str(old_record_ttl), " to ", str(new_ttl)
            )
        new_lines.append(temp)
    f = open(unsigned_zone_fn, "w")
    f.write("".join(new_lines))
    f.close()


def reload_named():
    result = subprocess.run("service named reload", shell=True, capture_output=True)
    if (
        "Reloading domain name service... named" in result.stdout.decode()
        and "done" in result.stdout.decode()
    ):
        return "Success"
    if result.stderr:
        raise Exception("Reloading resulted in error: " + result.stderr.decode())


def copy_changes_to_slave():
    files = os.listdir(ZONE_DIR)
    for file in files:
        result = subprocess.run(
            "cp " + ZONE_DIR + file + " " + ZONE_DIR_SECOND_NS,
            shell=True,
            capture_output=True,
        )
        if not result.stderr.decode():
            logger.logger.debug("Copied " + file + " to slave")
        else:
            logger.logger.error("Error: " + result.stderr.decode())


def parse_instructions(gt_instrs):
    parent_zone, zone = None, None
    ds_records = []
    record_ttl, rrsig_ttl, validity = None, None, None
    key_file = None
    ds_record = None
    for instr in gt_instrs:
        if instr.startswith("Parent zone"):
            parent_zone = identify_zone_from_instr(instr, parent=True)
            zone = identify_zone_from_instr(instr, parent=False)
            logger.logger.debug("Parent zone:", parent_zone, " zone: ", zone)
        elif "Configure the erroneous servers to pull from the master" in instr:
            # We are not supposed to pull from the master. as we are using Docker
            pass
        elif "Generate a new KSK key pair" in instr:
            cmd = instr.split("BIND command: ")[1][1:-1]
            key_file = generate_key_pair(cmd)
        elif "Generate a new ZSK key pair" in instr:
            cmd = instr.split("BIND command: ")[1][1:-1]
            key_file = generate_key_pair(cmd)
        elif "Generate a new key pair" in instr:
            cmd = instr.split("BIND command: ")[1][1:-1]
            key_file = generate_key_pair(cmd)
        # elif "Add the public key to the DNSKEY RRset" in instr:
        #     if key_file:
        #         add_dnskey_to_zone_file(key_file)
        elif "Generate the corresponding DS record" in instr:
            cmd = instr.split("BIND command: ")[1][1:-1]
            if key_file:
                ds_record = generate_ds_record(zone, cmd, key_file)
        elif (
            "Upload DS record in the parent zone" in instr
            or "Upload the DS record(s)" in instr
        ):
            if ds_record:
                upload_ds_record(parent_zone, ds_record)
                sign_parent_zone(parent_zone)
        elif (
            "Remove the DS record(s)" in instr
            or "Remove these extraneous DS record(s)" in instr
            or "Remove these incorrect DS record(s)" in instr  # tested
        ):
            key_tags = identify_key_tags_from_instr(instr)
            if parent_zone:
                for key_tag in key_tags:
                    remove_from_parent_zone(parent_zone, key_tag)
                sign_parent_zone(parent_zone)
        elif "remove the revoked dnskey(s)" in instr.lower():
            key_tags = identify_key_tags_from_instr(instr)
            for key_tag in key_tags:
                set_deletion_date_for_dnskey(zone, key_tag)
            pre_revoke_key_tags = identify_pre_revoke_key_tags_from_instr(instr)
            for key_tag in pre_revoke_key_tags:
                set_deletion_date_for_dnskey(zone, key_tag)
        elif "Resign the zone" in instr or "Sign the zone" in instr:
            cmd = instr.split("BIND command for manual signing: ")[1][1:-1]
            sign_zone(cmd)
        elif (
            "Resigning the zone should resolve the issue" in instr
            or "Resigning the zone by explicitly setting the iteration count to 0"
            in instr
        ):
            cmd = instr.split("BIND command for manual signing: ")[1][1:-1]
            sign_zone(cmd)
        elif "resign the parent zone which should typically resolve the issue" in instr:
            cmd = instr.split("BIND command for manual signing: ")[1][1:-1]
            sign_zone(cmd)
        elif "Generate the correct DS record(s)" in instr:
            key_tags = identify_key_tags_from_instr(instr)
            cmds = instr.split("BIND command: ")[1][1:-1].split("\n")
            if zone:
                files = os.listdir(X3LD_KEY_DIR + zone)
                for ind, key_tag in enumerate(key_tags):
                    for file in files:
                        if key_tag in file and ".key" in file:
                            cmd = cmds[ind]
                            fn = file.split(".key")[0]
                            ds_records.append(generate_ds_record(zone, cmd, fn))
                            break
        elif "Upload the correct DS record(s)" in instr:
            logger.logger.debug("ds", ds_records)
            if ds_records and parent_zone:
                for ds_record in ds_records:
                    print(ds_record)
                    upload_ds_record(parent_zone, ds_record)
                sign_parent_zone(parent_zone)
        elif "Your record TTL is" in instr and "Your signature TTL is" in instr:
            record_ttl, rrsig_ttl, validity = extract_ttl_and_validity(instr)
            logger.logger.debug("TTL params", record_ttl, rrsig_ttl, validity)
        elif "reducing your zone/record ttl" in instr.lower():
            if record_ttl and rrsig_ttl and validity:
                cmd = instr.split(
                    "BIND command for manual signing (use the `-e` flag to specify the signature validity, default is 30 days): "
                )[1][1:-1]
                if rrsig_ttl <= 300:
                    # resigning with a double signature validity
                    sign_zone_with_expiration(cmd, validity * 2)
                elif rrsig_ttl >= validity / 4:
                    # reduce zone ttl to make it 1/4th the validity
                    logger.logger.debug("Reduce zone ttl to make it 1/4th the validity")
                    zone = identify_zone_from_signzone(cmd)
                    reduce_zone_ttl_indi_format(
                        zone, record_ttl, rrsig_ttl, int(validity / 4)
                    )
                    sign_zone_with_expiration(cmd, validity)
                else:
                    # reduce zone ttl to match the validity
                    logger.logger.debug("Reduce zone ttl to 300s")
                    zone = identify_zone_from_signzone(cmd)
                    reduce_zone_ttl_indi_format(zone, record_ttl, rrsig_ttl, 300)
                    cmd = instr.split(
                        "BIND command for manual signing (use the `-e` flag to specify the signature validity, default is 30 days): "
                    )[1][1:-1]
                    sign_zone_with_expiration(cmd, validity)
    # After executing all the instructions
    copy_changes_to_slave()
    logger.logger.debug("\nSuccessfully executed all the instructions.\n")


def execute_instructions(gt_instrs):
    parse_instructions(gt_instrs)
