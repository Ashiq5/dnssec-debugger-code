from enum import IntEnum, Enum
from typing import List


class DnssecPriority(IntEnum):
    AFTER_DOMAIN_CREATION = 1
    AFTER_ZONEFILE_CREATION = 2
    AFTER_NSEC = 3
    AFTER_SIGNATURE = 4
    AFTER_PARENT_ZONEFILE_CREATION = 5
    REDO_WHOLE_PROCESS = 6
    LAST_AFTER_SIGNATURE = 7


class DnssecErrorType(Enum):
    # Olivier
    DIGEST_INVALID = (
        "induces DIGEST_INVALID and NO_SEP error when there is one KSK. "
        "just DIGEST_INVALID in case of multiple KSK with same algo. "
        "in case of multiple KSK with an unique algo having invalid digest, induces MISSING_RRSIG_FOR_ALG_DS and MISSING_RRSIG_FOR_ALG_DNSKEY."
    )
    REVOKE_DS = (
        "if one linked ksk is revoked then MISSING_SEP_FOR_ALG and NO_SEP. "
        "when one linked ksk is revoked among multiple ksks with same algo, then no error. "
        "when one linked ksk of an unique algo is revoked among multiple ksks, then MISSING_SEP_FOR_ALG, MISSING_RRSIG_FOR_ALG_DNSKEY, MISSING_RRSIG_FOR_ALG_DS."
    )
    REMOVE_RRSIG_DNSKEY = (
        "when there is one ksk and ksk rrsig is removed, then MISSING_SEP_FOR_ALG and NO_SEP are induced."
        "when there are multiple ksks and ksks rrsigs are removed, then MISSING_SEP_FOR_ALG and NO_SEP are induced."
        "when there are multiple ksks with unique algos and ksks rrsigs are removed, then MISSING_SEP_FOR_ALG, NO_SEP, MISSING_RRSIG_FOR_ALG_DNSKEY, MISSING_RRSIG_FOR_ALG_DS are induced"
    )
    REVOKED_RRSIG = "revoked-rrsig, i think it's duplicate of REVOKE_DS"
    LAST_NSEC_NOT_ZONE = "LAST_NSEC_NEXT_NOT_ZONE induced"
    MISSING_NSEC_FOR_NODATA = "missing-nsec-for-nodata"
    MISSING_NSEC_FOR_NXDOMAIN = "seems to be doing the same thing as REMOVE_NSEC_RECORD_A_SUBDOMAIN, not sure why needed?"
    NO_CLOSEST_ENCLOSER = "induces NO_CLOSEST_ENCLOSER error"
    NO_NSEC_MATCHING_SNAME = "no-nsec-matching-sname"
    NO_NSEC3_MATCHING_SNAME = "no-nsec3-matching-sname"
    REMOVE_RRSIG_ZSK = (
        "induces MISSING_RRSIG and NO_CLOSEST_ENCLOSER error with one ZSK and NSEC3. "
        "same case with multiple ZSKs same algo."
        "with multiple ZSKs and unique algo, MISSING_RRSIG, MISSING_RRSIG_FOR_ALG_DNSKEY, and WILDCARD_NOT_COVERED comes along."
    )
    SIGNATURE_INVALID = "induces SIGNATURE_INVALID error and NO_SEP as well since KSK signature is also made invalid"
    MAKE_KSK_ALGO_NOT_MATCHING = "make-ksk-algo-not-matching"
    REMOVE_ONE_ZSK = (
        "If only one zsk is present, induces MISSING_SEP_FOR_ALG, NO_SEP, MISSING_NSEC_FOR_NXDOMAIN, MISSING_RRSIG, MISSING_NSEC_FOR_NODATA. No error in case of multiple ZSKs with same algo. in case of a ZSK with an "
        "unique algo being removed, induces MISSING_RRSIG_FOR_ALG_DNSKEY and MISSING_RRSIG_FOR_ALG_DS."
    )
    REMOVE_ONE_KSK = (
        "If only one ksk is present, induces MISSING_SEP_FOR_ALG and NO_SEP. No error in case of multiple KSKs with same algo. in case of a KSK with an "
        "unique algo being removed, induces MISSING_SEP_FOR_ALG and MISSING_RRSIG_FOR_ALG_DS."
    )
    ADD_A_DS = "Adds a DS to the parent zone."
    SNAME_NOT_COVERED = "sname-not-covered"
    REMOVE_A_RECORD = "removes a record of specific type and subdomain. induces STYPE_IN_BITMAP error."
    REMOVE_NSEC_RECORD_A_SUBDOMAIN = "removes NSEC record of specific subdomain. thus creates SNAME_NOT_COVERED error for an NX domain that lies within this removed NSEC range."
    REMOVE_A_RECORD_FROM_DOMAIN_GEN = ("remove-a-record-from-domain-gen",)
    REMOVE_NSEC_AND_IP4_FOR_E_SUBDOMAIN = (
        "If subdomains E exists, remove A records and NSEC"
    )
    REMOVE_RRSIG_KSK = "Remove RRSIG generated from KSKs (except RRSIG DNSKEY)"
    REMOVE_DNSKEY_RECORDS = (
        "removes all dnskey and this creates MISSING_SEP_FOR_ALG, NO_SEP, MISSING_RRSIG'"
        "MISSING_NSEC_FOR_NXDOMAIN, MISSING_NSEC_FOR_NODATA"
    )

    REMOVE_ALL_NSEC = "Remove all NSEC records."
    REMOVE_LAST_NSEC3 = "Remove all NSEC3 records."

    REMOVE_Q_SUBDOMAIN_NSEC = "Remove NSEC from the subdomains 'q'"
    REMOVE_RRSIG_OF_SUBDOMAIN = "Remove all RRSIG for all subdomains"
    REVOKE_ONE_KSK = (
        "Revoke one KSK at the domain creation time, can be called mutliple time"
    )
    REVOKE_ONE_ZSK = (
        "Revoke one ZSK at the domain creation time, can be called mutliple time"
    )
    DNSKEY_MISSING_FROM_SERVERS = "Upload the correct ZoneFile to one NS, remove key and upload it to the second NS"
    REMOVE_RRSIG_FROM_AN_ALGO_DNSKEY = "Remove the RRSIG of DNSKEY signed by the KSKs"
    SIGNATURE_DOMAIN_WITHOUT_KEY = "Generate RRSIG from domain that does not have keys"
    ADD_A_ZSK = "Add a ZSK at the domain creation time, type if RSASHA256"
    REMOVE_RRSIG_FROM_AN_ALGO_DS = "Remove the RRSIG of DNSKEY signed by the ZSKs"

    # Ishtiaq
    NONZERO_ITER_COUNT = "nonzero-iter-count, website only"
    EXPIRED_RRSIG = "expired-rrsig"
    NOT_YET_VALID_RRSIG = "not-yet-valid-rrsig"
    ORIGINAL_TTL_EXCEEDED_RRSET = "original-ttl-exceeded-rrset"
    ORIGINAL_TTL_EXCEEDED_RRSIG = "original-ttl-exceeded-rrsig"
    TTL_BEYOND_EXPIRATION = "ttl-beyond-expiration"
    EXISTING_NAME_COVERED = "existing-name-covered, website only"
    SIGNER_NOT_ZONE_IN = "signer-not-zone-case-1"
    SIGNER_NOT_ZONE_OUT = "signer-not-zone-case-2"
    INVALID_NSEC3_HASH = "invalid-nsec3-hash, error!"
    EXISTING_TYPE_NOT_IN_BITMAP = "existing-type-not-in-bitmap"
    STYPE_IN_BITMAP = "stype-in-bitmap"
    REFERRAL_WITHOUT_NS = "referral-without-ns"
    REFERRAL_WITH_DS = "referral-with-ds"
    REFERRAL_WITH_SOA = "referral-with-soa"
    MISSING_NSEC_FOR_WILDCARD = "missing-nsec-for-wildcard"
    RRSIG_LABELS_EXCEED_RRSET_OWNER_LABELS_NONWC = (
        "rrsig-labels-exceed-rrset-non-wc, website only"
    )
    RRSIG_LABELS_EXCEED_RRSET_OWNER_LABELS_WC = "signature-invalid-case-2"

class DnssecError:
    def __init__(self, error: DnssecErrorType, priority):
        self.error_type = error
        self.priority = priority

    def get_error_type(self):
        return self.error_type

    def get_priority(self):
        return self.priority


class DnssecErrors:
    def __init__(self, errors_list: List[DnssecError]):
        self.errors = errors_list

    def get_priorities_equal(self, priority: DnssecPriority) -> List[DnssecError]:
        return [err for err in self.errors if err.get_priority() == priority]

    def get_priorities_inf(self, priority: DnssecPriority) -> List[DnssecError]:
        return [err for err in self.errors if err.get_priority() < priority]

    def get_priorities_sup(self, priority: DnssecPriority) -> List[DnssecError]:
        return [err for err in self.errors if err.get_priority() > priority]
