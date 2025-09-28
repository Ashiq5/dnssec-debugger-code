from typing import List

from .Meta import GrokDebugKeySet
from .GrokPath import DataPath, PathInfo, DataPathType
from .DnsStuff import DnsRdatas
from .GrokRRSIG import GrokRRSIGlist
from .GrokCommons import (
    GrokErrorList,
    GrokWarningList,
    GrokQueryOptionsList,
    GrokNsNamesList,
    GrokServersList,
)
from .GrokError import GrokError

debug_set = {
    "id",
    "description",
    "name",
    "servers",
    "ns_names",
    "query_options",
    "dname",
    "cname_owner",
    "cname_target",
    "status",
}


class GrokDnameInfo(
    GrokQueryOptionsList, GrokNsNamesList, GrokServersList, GrokRRSIGlist, DataPath
):
    def __init__(self, json_data: dict, path_info: PathInfo):
        DataPath.__init__(self, path_info)

        GrokQueryOptionsList.__init__(self, json_data=json_data)
        GrokNsNamesList.__init__(self, json_data=json_data)
        GrokServersList.__init__(self, json_data=json_data)
        GrokRRSIGlist.__init__(self, json_data=json_data)

        self.id = json_data.get("id")
        self.description = json_data.get("description")
        self.name = json_data.get("name")
        self.type = json_data.get("type")
        self.rdata = DnsRdatas(json_data.get("rdata"))

    def get_errors(self) -> List[GrokError]:
        err: List[GrokError] = []
        for rrsig in self.rrsig:
            err += rrsig.get_errors()

        return err


class GrokDname(
    GrokDebugKeySet, GrokQueryOptionsList, GrokNsNamesList, GrokServersList, DataPath
):
    def __init__(self, json_data: dict, path_info: PathInfo):
        DataPath.__init__(self, path_info)

        GrokQueryOptionsList.__init__(self, json_data=json_data)
        GrokNsNamesList.__init__(self, json_data=json_data)
        GrokServersList.__init__(self, json_data=json_data)

        self.id = json_data.get("id")
        self.description = json_data.get("description")
        self.name = json_data.get("name")
        self.cname_owner = json_data.get("cname_owner")
        self.cname_target = json_data.get("cname_target")
        self.status = json_data.get("status")
        self.dname_info = GrokDnameInfo(
            json_data.get("dname"),
            path_info=self.new_path(added_path="dname", data_type=DataPathType.dict),
        )

        GrokDebugKeySet.__init__(
            self, debug_set, list(json_data.keys()), self.__class__.__name__
        )

    def get_errors(self) -> list[GrokError]:
        res = []
        res += self.dname_info.get_errors()
        return res
