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
    "flags",
    "protocol",
    "algorithm",
    "key",
    "ttl",
    "key_length",
    "key_tag",
    "servers",
    "ns_names",
    "query_options",
    "errors",
    "warnings",
    "key_tag_pre_revoke",
}


class GrokDnsKey(
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
        self.description = json_data.get("description")
        self.flags = json_data.get("flags")
        self.protocol = json_data.get("protocol")
        self.algorithm = json_data.get("algorithm")
        self.key = json_data.get("key")
        self.ttl = json_data.get("ttl")
        self.key_length = json_data.get("key_length")
        self.key_tag = json_data.get("key_tag")
        self.key_tag_pre_revoke = json_data.get("key_tag_pre_revoke")

        GrokDebugKeySet.__init__(
            self, debug_set, list(json_data.keys()), self.__class__.__name__
        )

    def get_info(self):
        return {
            "key_tag": self.key_tag,
            "algorithm": self.algorithm,
            "key_flags": self.flags,
            "key_length": self.key_length,
            "key_tag_pre_revoke": self.key_tag_pre_revoke,
        }
