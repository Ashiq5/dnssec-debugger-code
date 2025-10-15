import datetime


def get_errcodes(zone_name, dom2err):
    err_codes = set()
    for domain in dom2err:
        # if len(domain) >= len(
        #     zone_name
        # ):  # taking errors only from zone and below and ignoring errors above the zone (ancestors) which should not be under admin's control
        if domain.endswith(zone_name):
            if dom2err[domain]:
                for path in dom2err[domain]:
                    # ignoring error in DS queries or DS insecurity proofs within the zone bcs they belong to the parent
                    # okay if it's not within the zone and belongs to the child zone itself
                    # if len(domain) == len(zone_name):
                    if domain == zone_name:
                        if domain + "/IN/DS" in path:
                            continue
                        # REFERRAL_WITH_DS type errors are available here
                        if "delegation -> insecurity_proof" in path:
                            for terr in dom2err[domain][path]:
                                if terr["code"] in {
                                    "REFERRAL_WITH_DS",
                                    "REFERRAL_WITHOUT_NS",
                                    "REFERRAL_WITH_SOA",
                                }:
                                    err_codes.add(terr["code"])
                            continue

                    for err in dom2err[domain][path]:
                        err_codes.add(err["code"])
    return err_codes


KEY2ALGO_MAPPING = {
    1: "RSAMD5",
    3: "DSASHA1",
    5: "RSASHA1",
    6: "DSANSEC3SHA1",
    7: "NSEC3RSASHA1",
    8: "RSASHA256",
    10: "RSASHA512",
    13: "ECDSAP256SHA256",
    14: "ECDSAP384SHA384",
    15: "ED25519",
    16: "ED448",
}
PDNS_KEY2ALGO_MAPPING = {
    5: "rsasha1",
    7: "rsasha1-nsec3-sha1",
    8: "rsasha256",
    10: "rsasha512",
    13: "ecdsa256",
    14: "ecdsa384",
    15: "ed25519",
    16: "ed448",
}

DEFAULT_ALGORITHM_TEXT = "ECDSAP256SHA256"
PDNS_DEFAULT_ALGORITHM_TEXT = "ecdsa256"
DEFAULT_ALGORITHM_NUMBER = 13
DEFAULT_KEYSIZE = 1024
keysize_required_algorithms = {
    "RSAMD5",
    "DSASHA1",
    "RSASHA1",
    "DSANSEC3SHA1",
    "RSASHA1",
    "NSEC3RSASHA1",
    "RSASHA256",
    "RSASHA512",
}
pdns_keysize_required_algorithms = {
    "rsasha1",
    "rsasha1-nsec3-sha1",
    "rsasha256",
    "rsasha512",
}
CAT = {
    "DoE": {
        "MISSING_NSEC_FOR_NODATA",
        "MISSING_NSEC_FOR_NXDOMAIN",
        "MISSING_NSEC_FOR_WILDCARD",
        "NO_NSEC_MATCHING_SNAME",
        "NO_NSEC3_MATCHING_SNAME",
        "SNAME_COVERED",
        "SNAME_NOT_COVERED",
        "WILDCARD_COVERED",
        "WILDCARD_NOT_COVERED",
        "EXISTING_NAME_COVERED",
        "INCONSISTENT_NXDOMAIN_ANCESTOR",
        "NO_CLOSEST_ENCLOSER",
        "NEXT_CLOSEST_ENCLOSER_NOT_COVERED",
        "OPT_OUT_FLAG_NOT_SET",
        "EXISTING_TYPE_NOT_IN_BITMAP",
        "REFERRAL_WITHOUT_NS",
        "REFERRAL_WITH_DS",
        "REFERRAL_WITH_SOA",
        "INVALID_NSEC3_HASH",
        "INVALID_NSEC3_OWNER_NAME",
        "LAST_NSEC_NEXT_NOT_ZONE",
        "STYPE_IN_BITMAP",
        "NONZERO_NSEC3_ITERATION_COUNT",
        "UNSUPPORTED_NSEC3_ALGORITHM",
    },
    "RRSIG": {
        "RRSIG_BAD_LENGTH_ECDSA256",
        "RRSIG_BAD_LENGTH_ECDSA384",
        "SIGNER_NOT_ZONE",
        "RRSIG_LABELS_EXCEED_RRSET_OWNER_LABELS",
        "SIGNATURE_INVALID",
        "MISSING_RRSIG",
        "MISSING_RRSIG_FOR_ALG_DNSKEY",
        "MISSING_RRSIG_FOR_ALG_DS",
    },
    "Server": {
        "SERVER_UNRESPONSIVE_TCP",
        "SERVER_UNRESPONSIVE_UDP",
        "UNABLE_TO_RETRIEVE_DNSSEC_RECORDS",
        "DNSSEC_DOWNGRADE_DO_CLEARED",
        "DNSSEC_DOWNGRADE_EDNS_DISABLED",
        "ERROR_WITH_EDNS",
        "ERROR_WITH_EDNS_FLAG",
        "ERROR_WITH_EDNS_OPTION",
        "ERROR_WITHOUT_REQUEST_FLAG",
        "RECURSION_NOT_AVAILABLE",
        "SERVER_INVALID_RESPONSE_TCP",
        "SERVER_INVALID_RESPONSE_UDP",
        "NOT_AUTHORITATIVE",
        "SERVER_NOT_AUTHORITATIVE",
        "UPWARD_REFERRAL",
        "REFERRAL_FOR_DS_QUERY",
    },
    "TTL": {
        "ORIGINAL_TTL_EXCEEDED_RRSET",
        "ORIGINAL_TTL_EXCEEDED_RRSIG",
        "TTL_BEYOND_EXPIRATION",
    },
    "DNSKEY": {
        "DNSKEY_REVOKED_RRSIG",
        "DNSKEY_BAD_LENGTH_ECDSA256",
        "DNSKEY_BAD_LENGTH_ECDSA384",
        "DNSKEY_MISSING_FROM_SERVERS",
        "DNSKEY_REVOKED_DS",
        "DNSKEY_REVOKED_RRSIG",
        "REVOKED_NOT_SIGNING",
        "DNSKEY_ZERO_LENGTH",
        "NO_TRUST_ANCHOR_SIGNING",
    },
    "Timing": {"INCEPTION_IN_FUTURE", "EXPIRATION_IN_PAST"},
    "DS": {"MISSING_SEP_FOR_ALG", "DIGEST_INVALID", "NO_SEP"},
    "NS": set([]),
    "SOA": set([]),
    "CNAME": set([]),
}
companion_errors = ["MISSING_RRSIG_FOR_ALG_DS", "NO_SEP", "REVOKED_NOT_SIGNING"]

DNSSECRelatedErrors = []
for key in CAT:
    if key == "Server":
        continue
    for err in CAT[key]:
        if err == "NO_TRUST_ANCHOR_SIGNING":
            continue
        DNSSECRelatedErrors.append(err)


def convert_to_epoch_time(dt_str):
    # Parse using the format: YYYYMMDDHHMMSS
    dt = datetime.datetime.strptime(dt_str, "%Y%m%d%H%M%S")

    # Assume the parsed time is UTC; attach UTC timezone
    dt_utc = dt.replace(tzinfo=datetime.timezone.utc)

    # Convert to Unix timestamp (float). Use int(...) if you want an integer.
    epoch_time = dt_utc.timestamp()

    return epoch_time
