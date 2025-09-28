from typing import List

from .Meta import GrokDebugKeySet

error_debut_set = {"description", "code", "servers", "query_options"}


class DnsError(GrokDebugKeySet):
    def __init__(self, json_data: dict):
        self.desription = json_data.get("desription")
        self.code = json_data.get("code")
        self.servers = json_data.get("servers")
        self.query_options = json_data.get("query_option")

        super().__init__(
            error_debut_set, list(json_data.keys()), self.__class__.__name__
        )


warining_debut_set = {"description", "code", "servers", "query_options"}


class DnsWaring(GrokDebugKeySet):
    def __init__(self, json_data: dict):
        self.descrption = json_data.get("description")
        self.code = json_data.get("code")
        self.servers = json_data.get("servers")
        self.query_options = json_data.get("query_option")

        super().__init__(
            warining_debut_set, list(json_data.keys()), self.__class__.__name__
        )


class DnsRdata:
    def __init__(self, rdata):
        self.rdata = rdata


class DnsRdatas:
    def __init__(self, rdatas: List):
        self.rdatas: List[DnsRdata] = []
        for rdata in rdatas:
            self.rdatas.append(DnsRdata(rdata))
