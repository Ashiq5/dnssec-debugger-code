from typing import List
from .Meta import GrokDebugKeySet
from .GrokPath import DataPath, PathInfo, DataPathType
from .GrokError import GrokError
from .GrokWarning import GrokWarning
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
    "algorithm",
    "key_tag",
    "digest_type",
    "digest",
    "ttl",
    "status",
    "servers",
    "ns_names",
    "query_options",
    "warnings",
    "errors",
}


class GrokDS(
    GrokDebugKeySet,
    GrokErrorList,
    GrokWarningList,
    GrokQueryOptionsList,
    GrokNsNamesList,
    GrokServersList,
    DataPath,
):
    def __init__(self, json_data: dict, path_info: PathInfo):
        DataPath.__init__(self, path_info)

        GrokErrorList.__init__(self, json_data=json_data)
        GrokWarningList.__init__(self, json_data=json_data)
        GrokQueryOptionsList.__init__(self, json_data=json_data)
        GrokNsNamesList.__init__(self, json_data=json_data)
        GrokServersList.__init__(self, json_data=json_data)

        self.id = json_data.get("id")
        self.algorithm = json_data.get("algorithm")
        self.key_tag = json_data.get("key_tag")
        self.status = json_data.get("status")
        self.ttl = json_data.get("ttl")

        GrokDebugKeySet.__init__(
            self, debug_set, list(json_data.keys()), self.__class__.__name__
        )

    def get_ds_info(self):
        return {"key_tag": self.key_tag, "algorithm": self.algorithm}
