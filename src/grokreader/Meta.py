from enum import Enum
from functools import cmp_to_key
from typing import List
from publicsuffixlist import PublicSuffixList
import tldextract

DEBUG = False


class IpString(str):
    def __new__(cls, value):
        return str.__new__(cls, value)


class GrokDebugKeySet:
    def __init__(self, debug_set, keys, class_name):
        if DEBUG:
            for key in keys:
                if key not in debug_set:
                    raise Exception(
                        f"class : {class_name} class , '{key}' not in {debug_set}"
                    )


psl = PublicSuffixList()


def revert_domain(domain):
    return domain.lower().strip(".").split(".")[::-1]


def domain_key_as_nsec(domain_a: str, domain_b: str):
    reverted_a = revert_domain(domain_a)
    reverted_b = revert_domain(domain_b)
    for i in range(0, min(len(reverted_a), len(reverted_b))):
        if reverted_a[i] != reverted_b[i]:
            return 1 if reverted_a[i] > reverted_b[i] else -1
    return 1 if len(reverted_a) > len(reverted_b) else -1


def sort_as_nsec(domains: List[str]):
    return sorted(domains, key=cmp_to_key(domain_key_as_nsec))


def is_root_or_tld(domain):
    if domain == ".":  # excluding root and TLD
        return True
    if psl and psl.publicsuffix(domain) == domain.strip("."):
        return True

    return False
    # tld_extraction = tldextract.extract(domain)
    # return tld_extraction.suffix != '' and tld_extraction.domain == domain == ''
