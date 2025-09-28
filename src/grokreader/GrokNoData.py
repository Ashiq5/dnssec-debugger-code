from typing import List
from .Meta import GrokDebugKeySet
from .GrokPath import DataPath, PathInfo, DataPathType
from .GrokError import GrokError
from .GrokWarning import GrokWarning
from .GrokProof import GrokProof
from .GrokSoa import GrokSoa
from .GrokCommons import (
    GrokErrorList,
    GrokWarningList,
    GrokQueryOptionsList,
    GrokNsNamesList,
    GrokServersList,
)

debug_set = {
    "id",
    "servers",
    "ns_names",
    "query_options",
    "cookie_status",
    "proof",
    "soa",
    "errors",
    "warnings",
}


class GrokNoData(
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
        self.cookie_status = json_data.get("cookie_status")
        self.proof: List[GrokProof] = []
        for index, p in enumerate(json_data.get("proof", [])):
            self.proof.append(
                GrokProof(
                    p,
                    path_info=self.new_path(
                        added_path="proof",
                        data_type=DataPathType.list,
                        list_index=index,
                    ),
                )
            )

        self.soa: List[GrokSoa] = []
        for index, s in enumerate(json_data.get("soa", [])):
            self.soa.append(
                GrokSoa(
                    s,
                    path_info=self.new_path(
                        added_path="soa", data_type=DataPathType.list, list_index=index
                    ),
                )
            )

        GrokDebugKeySet.__init__(
            self, debug_set, list(json_data.keys()), self.__class__.__name__
        )

    def get_denial_of_existence_parameters(self):
        for grok_proof in self.proof:
            res = grok_proof.get_denial_of_existence_parameters()
            if res is not None:
                return res

        return None


class GrokNxDomain(GrokNoData):
    def __init__(self, json_data: dict, path_info: PathInfo):
        super().__init__(json_data=json_data, path_info=path_info)
