from ZReplicator import DnssecError, DnssecErrorType, DnssecPriority

nnic = DnssecError(
    error=DnssecErrorType.NONZERO_ITER_COUNT, priority=DnssecPriority.AFTER_NSEC
)

exp = DnssecError(
    error=DnssecErrorType.EXPIRED_RRSIG, priority=DnssecPriority.AFTER_ZONEFILE_CREATION
)
inc = DnssecError(
    error=DnssecErrorType.NOT_YET_VALID_RRSIG,
    priority=DnssecPriority.AFTER_ZONEFILE_CREATION,
)
otert = DnssecError(
    error=DnssecErrorType.ORIGINAL_TTL_EXCEEDED_RRSET,
    priority=DnssecPriority.LAST_AFTER_SIGNATURE,
)
oterg = DnssecError(
    error=DnssecErrorType.ORIGINAL_TTL_EXCEEDED_RRSIG,
    priority=DnssecPriority.LAST_AFTER_SIGNATURE,
)
texp = DnssecError(
    error=DnssecErrorType.TTL_BEYOND_EXPIRATION, priority=DnssecPriority.LAST_AFTER_SIGNATURE
)
ens = DnssecError(
    error=DnssecErrorType.EXISTING_NAME_COVERED, priority=DnssecPriority.AFTER_SIGNATURE
)
snzi = DnssecError(
    error=DnssecErrorType.SIGNER_NOT_ZONE_IN, priority=DnssecPriority.AFTER_SIGNATURE
)
snzo = DnssecError(
    error=DnssecErrorType.SIGNER_NOT_ZONE_OUT, priority=DnssecPriority.AFTER_SIGNATURE
)
enb = DnssecError(
    error=DnssecErrorType.EXISTING_TYPE_NOT_IN_BITMAP,
    priority=DnssecPriority.AFTER_SIGNATURE,
)
sib = DnssecError(
    error=DnssecErrorType.STYPE_IN_BITMAP, priority=DnssecPriority.AFTER_SIGNATURE
)
rwd = DnssecError(
    error=DnssecErrorType.REFERRAL_WITH_DS, priority=DnssecPriority.AFTER_SIGNATURE
)
rws = DnssecError(
    error=DnssecErrorType.REFERRAL_WITH_SOA, priority=DnssecPriority.AFTER_SIGNATURE
)
rwn = DnssecError(
    error=DnssecErrorType.REFERRAL_WITHOUT_NS, priority=DnssecPriority.AFTER_SIGNATURE
)
mnw = DnssecError(
    error=DnssecErrorType.MISSING_NSEC_FOR_WILDCARD,
    priority=DnssecPriority.AFTER_SIGNATURE,
)
rlnwc = DnssecError(
    error=DnssecErrorType.RRSIG_LABELS_EXCEED_RRSET_OWNER_LABELS_NONWC,
    priority=DnssecPriority.AFTER_SIGNATURE,
)
rlwc = DnssecError(
    error=DnssecErrorType.RRSIG_LABELS_EXCEED_RRSET_OWNER_LABELS_WC,
    priority=DnssecPriority.AFTER_SIGNATURE,
)
# invnh = DnssecError(
#     error=DnssecErrorType.INVALID_NSEC3_HASH, priority=DnssecPriority.AFTER_SIGNATURE
# )
# ORIGINAL_TTL_EXCEEDED_RRSIG

make_digest_invalid = DnssecError(
    error=DnssecErrorType.DIGEST_INVALID,
    priority=DnssecPriority.AFTER_ZONEFILE_CREATION,
)
remove_a_ksk = DnssecError(
    error=DnssecErrorType.REMOVE_ONE_KSK,
    priority=DnssecPriority.AFTER_PARENT_ZONEFILE_CREATION,
)

add_a_ds = DnssecError(
    error=DnssecErrorType.ADD_A_DS,
    priority=DnssecPriority.AFTER_PARENT_ZONEFILE_CREATION,
)

remove_a_zsk = DnssecError(
    error=DnssecErrorType.REMOVE_ONE_ZSK,
    priority=DnssecPriority.AFTER_PARENT_ZONEFILE_CREATION,
)

revoke_a_ksk = DnssecError(
    error=DnssecErrorType.REVOKE_ONE_KSK, priority=DnssecPriority.AFTER_DOMAIN_CREATION
)

revoke_a_zsk = DnssecError(
    error=DnssecErrorType.REVOKE_ONE_ZSK, priority=DnssecPriority.AFTER_DOMAIN_CREATION
)
remove_dnskey_rrsig = DnssecError(
    error=DnssecErrorType.REMOVE_RRSIG_DNSKEY, priority=DnssecPriority.AFTER_SIGNATURE
)

nsec_remove_apex = DnssecError(
    error=DnssecErrorType.LAST_NSEC_NOT_ZONE, priority=DnssecPriority.AFTER_NSEC
)

remove_nsec_for_nodata = DnssecError(
    error=DnssecErrorType.REMOVE_NSEC_AND_IP4_FOR_E_SUBDOMAIN,
    priority=DnssecPriority.AFTER_NSEC,
)

make_signature_invalid = DnssecError(
    error=DnssecErrorType.SIGNATURE_INVALID, priority=DnssecPriority.AFTER_SIGNATURE
)

add_a_zsk = DnssecError(
    error=DnssecErrorType.ADD_A_ZSK, priority=DnssecPriority.AFTER_DOMAIN_CREATION
)

remove_last_nsec3_parent_and_children = DnssecError(
    error=DnssecErrorType.NO_CLOSEST_ENCLOSER, priority=DnssecPriority.AFTER_NSEC
)


missing_rrsig_for_alg_dnskey = DnssecError(
    error=DnssecErrorType.REMOVE_RRSIG_FROM_AN_ALGO_DNSKEY,
    priority=DnssecPriority.AFTER_SIGNATURE,
)


missing_rrsig_for_alg_ds = DnssecError(
    error=DnssecErrorType.REMOVE_RRSIG_FROM_AN_ALGO_DS,
    priority=DnssecPriority.AFTER_SIGNATURE,
)

remove_all_nsec = DnssecError(
    error=DnssecErrorType.REMOVE_ALL_NSEC, priority=DnssecPriority.AFTER_NSEC
)

remove_last_nsec3 = DnssecError(
    error=DnssecErrorType.REMOVE_LAST_NSEC3, priority=DnssecPriority.AFTER_NSEC
)
remove_all_sub_rrsig = DnssecError(
    error=DnssecErrorType.REMOVE_RRSIG_OF_SUBDOMAIN,
    priority=DnssecPriority.AFTER_SIGNATURE,
)
remove_subdomain_q_nsec_record = DnssecError(
    error=DnssecErrorType.REMOVE_Q_SUBDOMAIN_NSEC, priority=DnssecPriority.AFTER_NSEC
)
make_a_dnskey_missing_from_one_server = DnssecError(
    error=DnssecErrorType.DNSKEY_MISSING_FROM_SERVERS,
    priority=DnssecPriority.REDO_WHOLE_PROCESS,
)

"""
    It seems that the errors can be removed.
We keep them as comment if test does not pass anymore.

dnskey_revoked_rrsig = DnssecError(
    error=DnssecErrorType.REVOKED_RRSIG, priority=DnssecPriority.AFTER_NSEC
)
         
missing_nsec_for_nodata = DnssecError(
    error=DnssecErrorType.MISSING_NSEC_FOR_NXDOMAIN, priority=DnssecPriority.AFTER_NSEC
)

no_nsec_matching_sname = DnssecError(
    error=DnssecErrorType.NO_NSEC_MATCHING_SNAME, priority=DnssecPriority.AFTER_NSEC
)

missing_rrsig_mka = DnssecError(
    error=DnssecErrorType.REMOVE_RRSIG_ZSK, priority=DnssecPriority.AFTER_SIGNATURE
)

remove_nsec_record_subdomain_a = DnssecError(
    error=DnssecErrorType.REMOVE_NSEC_RECORD_A_SUBDOMAIN,
    priority=DnssecPriority.AFTER_NSEC,
)

remove_dnskey_entries = DnssecError(
    error=DnssecErrorType.REMOVE_DNSKEY_RECORDS,
    priority=DnssecPriority.AFTER_ZONEFILE_CREATION,
)

# TODO: what's the difference with remove_dnskey_rrsig?
missing_rrsig_mra = DnssecError(
    error=DnssecErrorType.REMOVE_RRSIG_DNSKEY, priority=DnssecPriority.AFTER_SIGNATURE
)

"""
