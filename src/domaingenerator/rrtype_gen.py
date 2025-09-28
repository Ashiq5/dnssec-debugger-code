import datetime
import random
from typing import List

from faker import Faker


class RRtypeGen:
    """
    Base class for generating different types of DNS records (RRtypes).
    This handles the common logic for record count and character limits.
    Subclasses should implement the `generate_content` method.
    """

    rrtype = None

    def __init__(self, nb_records: int = None, bound: tuple[int, int] = None):
        """
        :param nb_records: Number of records to generate.
        :param bound: A tuple (lower_bound, upper_bound) defining the range for the number of records.
                      If not provided, the default range is (1,5). If nb_records is None, a random value
                      within the range is selected.
        """
        bound = (1, 5) if bound is None or bound[0] > bound[1] else bound
        self.lower_bound = bound[0]
        self.upper_bound = bound[1]
        self.content = []

        # Determine the number of records to generate
        self.nb_records = (
            random.randint(self.lower_bound, self.upper_bound)
            if nb_records is None
            else nb_records
        )
        self.generate()

    def generate(self):
        """Generate the DNS records."""
        for _ in range(self.nb_records):
            self.content.append(self.generate_content())
        return self.content

    def generate_content(self):
        """This method should be implemented by subclasses to generate specific record content."""
        raise NotImplementedError("Subclasses should implement this method.")

    def get_content(self):
        """Return the generated DNS record content."""
        return self.content

    def __str__(self):
        """Custom string representation including RRtype."""
        return f"{self.rrtype} Records: {self.get_content()}"


class AContent(RRtypeGen):
    """Generate IPv4 records."""

    rrtype = "A"

    def generate_content(self):
        return Faker().ipv4()


class AAAAContent(RRtypeGen):
    """Generate IPv6 records."""

    rrtype = "AAAA"

    def generate_content(self):
        return Faker().ipv6()


class TXTContent(RRtypeGen):
    """Generate TXT records with a random string."""

    rrtype = "TXT"
    max_txt_length = 50

    def generate_content(self):
        return "".join(Faker().random_letters(random.randint(1, self.max_txt_length)))


class NSContent(RRtypeGen):
    """Generate NS records."""

    rrtype = "NS"

    def __init__(self, nameservers: List[str] = []):
        super().__init__()
        for ns in set(nameservers):
            self.content.append(ns)

    def get_nameservers(self):
        return [x for x in self.content if x is not None]

    def generate_content(self):
        pass


class OtherContent(RRtypeGen):
    """Generate other records not yet implemented."""

    def __init__(self, type: str, content: List[str]):
        super().__init__()
        self.rrtype = type
        self.content = content

    def generate_content(self):
        pass


class SOAContent(RRtypeGen):
    """Generate SOA records."""

    rrtype = "SOA"

    def __init__(
        self,
        primary_ns: str = "ns.hureau.com.",
        admin_email: str = "admin.hureau.com.",
        serial: int = int(
            datetime.datetime.strftime(datetime.datetime.now(), "%y%m%d%H%M")
        ),
        refresh: int = 36000,
        retry: int = 86400,
        expire: int = 2419200,
        neg_cache: int = 604800,
    ):
        super().__init__()
        self.content = None

        self.primary_ns = primary_ns
        self.admin_email = admin_email
        self.serial = serial
        self.refresh = refresh
        self.retry = retry
        self.expire = expire
        self.neg_cache = neg_cache

    def generate_content(self):
        pass

    def get_content(self):
        return {
            "primary_ns": self.primary_ns,
            "admin_email": self.admin_email,
            "serial": self.serial,
            "refresh": self.refresh,
            "retry": self.retry,
            "expire": self.expire,
            "neg_cache": self.neg_cache,
        }


class EMPTYContent(RRtypeGen):
    def __init__(self, rrtype: str, description: str):
        self.rrtype = rrtype
        self.description = description

    def generate_content(self):
        pass

    def get_content(self):
        return self.description
