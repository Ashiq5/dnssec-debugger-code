from typing import List
from .Meta import GrokDebugKeySet
from .GrokError import GrokError
from .GrokWarning import GrokWarning
from .GrokCommons import (
    GrokErrorList,
    GrokWarningList,
    GrokQueryOptionsList,
    GrokNsNamesList,
    GrokServersList,
)
from .GrokError import GrokError
from .GrokPath import DataPath, PathInfo, DataPathType

debug_set = {
    "id",
    "description",
    "signer",
    "algorithm",
    "key_tag",
    "original_ttl",
    "labels",
    "inception",
    "expiration",
    "signature",
    "status",
    "servers",
    "ns_names",
    "ttl",
    "query_options",
    "warnings",
    "errors",
}


class GrokRRSIG(
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
        self.signer = json_data.get("signer")
        self.algorithm = json_data.get("algorithm")
        self.key_tag = json_data.get("key_tag")
        self.original_ttl = json_data.get("original_ttl")
        self.labels = json_data.get("labels")
        self.inception = json_data.get("inception")
        self.expiration = json_data.get("expiration")
        self.signature = json_data.get("signature")
        self.status = json_data.get("status")
        self.ttl = json_data.get("ttl")
        GrokDebugKeySet.__init__(
            self, debug_set, list(json_data.keys()), self.__class__.__name__
        )


class GrokRRSIGlist:
    rrsig: list[GrokRRSIG] = None

    def __init__(self, json_data):
        self.rrsig = []
        for index, rrsig in enumerate(json_data.get("rrsig", [])):
            self.rrsig.append(
                GrokRRSIG(
                    rrsig,
                    path_info=self.new_path(
                        added_path="", data_type=DataPathType.list, list_index=index
                    ),
                )
            )

    def get_rrsig_signers(self):
        signers = []
        for rrsig in self.rrsig:
            signers.append(f"{rrsig.algorithm}/{rrsig.key_tag}")

        return signers
