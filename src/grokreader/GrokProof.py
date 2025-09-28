from typing import List
from .Meta import GrokDebugKeySet
from .GrokPath import DataPath, PathInfo, DataPathType
from .GrokError import GrokError
from .GrokWarning import GrokWarning
from .GrokCovering import GrokCovering
from .GrokNsec import GrokNsec
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
    "status",
    "servers",
    "ns_names",
    "query_options",
    "sname_covering",
    "nsec",
    "nsec3",
    "opt_out",
    "next_closest_encloser",
    "closest_encloser",
    "next_closest_encloser",
    "next_closest_encloser_covering",
    "next_closest_encloser_hash",
    "wildcard_hash",
    "warnings",
    "errors",
    "closest_encloser_hash",
    "superfluous_closest_encloser",
    "wildcard_covering",
    "sname_nsec_match",
    "sname_hash",
    "closest_encloser_digest",
    "wildcard",
    "wildcard_nsec_match",
}


class GrokProof(
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

        self.status = json_data.get("status")
        self.sname_covering: GrokCovering = None
        self.nsec: List[GrokNsec] = []
        self.nsec3: List[GrokNsec] = []
        self.opt_out = json_data.get("opt_out")
        self.closest_encloser = json_data.get("closest_encloser")
        self.next_closest_encloser = json_data.get("next_closest_encloser")
        self.next_closest_encloser_covering = None
        self.closest_encloser_hash = json_data.get("closest_encloser_hash")
        self.sname_nsec_match = json_data.get("sname_nsec_match")
        self.sname_hash = json_data.get("sname_hash")
        self.closest_encloser_digest = json_data.get("closest_encloser_digest")
        self.wildcard = json_data.get("wildcard")
        self.wildcard_nsec_match = json_data.get("wildcard_nsec_match")

        if "next_closest_encloser_covering" in json_data:
            self.next_closest_encloser = GrokCovering(
                json_data.get("next_closest_encloser_covering"),
                path_info=self.new_path(
                    added_path="next_closest_encloser_covering",
                    data_type=DataPathType.dict,
                ),
            )
        self.wildcard_hash = json_data.get("wildcard_hash")

        self.superfluous_closest_encloser = json_data.get(
            "superfluous_closest_encloser"
        )

        self.sname_covering = None
        if "sname_covering" in json_data:
            self.sname_covering = GrokCovering(
                json_data["sname_covering"],
                path_info=self.new_path(
                    added_path="sname_covering", data_type=DataPathType.dict
                ),
            )

        self.wildcard_covering = None
        if "wildcard_covering" in json_data:
            self.wildcard_covering = GrokCovering(
                json_data["wildcard_covering"],
                path_info=self.new_path(
                    added_path="wildcard_covering", data_type=DataPathType.dict
                ),
            )

        for index, n in enumerate(json_data.get("nsec", [])):
            self.nsec.append(
                GrokNsec(
                    n,
                    path_info=self.new_path(
                        added_path="nsec", data_type=DataPathType.list, list_index=index
                    ),
                )
            )

        for index, n in enumerate(json_data.get("nsec3", [])):
            self.nsec3.append(
                GrokNsec(
                    n,
                    path_info=self.new_path(
                        added_path="nsec3",
                        data_type=DataPathType.list,
                        list_index=index,
                    ),
                )
            )

        GrokDebugKeySet.__init__(
            self, debug_set, list(json_data.keys()), self.__class__.__name__
        )

    def get_denial_of_existence_parameters(self):
        if len(self.nsec) != 0 and len(self.nsec3) != 0:
            raise Exception("Should not happens")

        if len(self.nsec) != 0:
            return "NSEC"

        if len(self.nsec3) != 0:
            for nsec3 in self.nsec3:
                res = nsec3.get_nsec_3_param()
                if res is not None:
                    return res

        return None


class GrokWildcardProof(DataPath):
    def __init__(self, proof: dict, name, path_info: PathInfo):
        DataPath.__init__(self, path_info)

        self.name = name
        self.proof: List[GrokProof] = []
        for index, p in enumerate(proof):
            self.proof.append(
                GrokProof(
                    p,
                    path_info=self.new_path(
                        added_path="", data_type=DataPathType.list, list_index=index
                    ),
                )
            )

    def get_errors(self):
        res: List[GrokError] = []
        for p in self.proof:
            res += p.get_errors()

        return res
