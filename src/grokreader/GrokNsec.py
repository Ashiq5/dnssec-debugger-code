from typing import List
from .Meta import GrokDebugKeySet
from .GrokPath import DataPath, PathInfo, DataPathType
from .GrokError import GrokError
from .GrokWarning import GrokWarning
from .DnsStuff import DnsRdatas
from .GrokRRSIG import GrokRRSIGlist
from .GrokCommons import (
    GrokErrorList,
    GrokWarningList,
    GrokQueryOptionsList,
    GrokNsNamesList,
    GrokServersList,
)


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
    "errors",
    "warnings",
}


class GrokNsec(
    GrokDebugKeySet,
    GrokErrorList,
    GrokWarningList,
    GrokQueryOptionsList,
    GrokNsNamesList,
    GrokServersList,
    GrokRRSIGlist,
    DataPath,
):
    def __init__(self, json_data: dict, path_info: PathInfo):
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
        self.rdata = DnsRdatas(json_data.get("rdata"))

        GrokDebugKeySet.__init__(
            self, debug_set, list(json_data.keys()), self.__class__.__name__
        )

    def get_errors(self) -> List[GrokError]:
        err = GrokErrorList.get_errors(self)
        for rrsig in self.rrsig:
            err.extend(rrsig.get_errors())

        return err

    def get_nsec_3_param(self):
        return self.rdata.rdatas[0].rdata
