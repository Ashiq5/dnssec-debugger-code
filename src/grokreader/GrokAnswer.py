from typing import List
from .Meta import GrokDebugKeySet
from .GrokPath import DataPath, PathInfo, DataPathType
from .GrokCommons import (
    GrokErrorList,
    GrokWarningList,
    GrokQueryOptionsList,
    GrokNsNamesList,
    GrokServersList,
)
from .GrokRRSIG import GrokRRSIGlist

from .DnsStuff import DnsRdatas
from .GrokCookies import GrokCookiesList
from .GrokDname import GrokDname
from .GrokProof import GrokWildcardProof
from .GrokError import GrokError

debug_set = {
    "id",
    "description",
    "name",
    "ttl",
    "type",
    "rdata",
    "servers",
    "ns_names",
    "query_options",
    "rrsig",
    "cookie_status",
    "errors",
    "warnings",
    "wildcard_proof",
    "dname",
}


class GrokAnswer(
    GrokDebugKeySet,
    GrokErrorList,
    GrokWarningList,
    GrokQueryOptionsList,
    GrokNsNamesList,
    GrokServersList,
    GrokRRSIGlist,
    DataPath,
):
    def __init__(self, json_data, path_info: PathInfo):
        DataPath.__init__(self, path_info)

        GrokErrorList.__init__(self, json_data=json_data)
        GrokWarningList.__init__(self, json_data=json_data)
        GrokQueryOptionsList.__init__(self, json_data=json_data)
        GrokNsNamesList.__init__(self, json_data=json_data)
        GrokServersList.__init__(self, json_data=json_data)
        GrokRRSIGlist.__init__(self, json_data=json_data)

        self.id = json_data.get("id")
        self.description = json_data.get("description")
        self.name = json_data.get("name")
        self.ttl = json_data.get("ttl")
        self.type = json_data.get("type")
        self.rdatas = DnsRdatas(json_data.get("rdata", []))
        self.cookie_status = GrokCookiesList(json_data.get("cookie_status", []))

        self.wildcard_proof: List[GrokWildcardProof] = []
        self.dname: List[GrokDname] = []

        for index, wildcard_proof in enumerate(
            json_data.get("wildcard_proof", dict()).keys()
        ):

            self.wildcard_proof.append(
                GrokWildcardProof(
                    json_data["wildcard_proof"][wildcard_proof],
                    wildcard_proof,
                    path_info=self.new_path(
                        added_path="wildcard_proof",
                        data_type=DataPathType.list,
                        list_index=index,
                    ),
                )
            )

        for index, dname in enumerate(json_data.get("dname", [])):
            self.dname.append(
                GrokDname(
                    dname,
                    path_info=self.new_path(
                        added_path="dname",
                        data_type=DataPathType.list,
                        list_index=index,
                    ),
                )
            )

        GrokDebugKeySet.__init__(
            self, debug_set, list(json_data.keys()), self.__class__.__name__
        )

    def get_errors(self) -> List[GrokError]:
        err = GrokErrorList.get_errors(self)
        for rrsig in self.rrsig:
            err += rrsig.get_errors()
        for wildcard_proof in self.wildcard_proof:
            err += wildcard_proof.get_errors()
        return err
