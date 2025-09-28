from typing import List
from .Meta import GrokDebugKeySet
from .GrokPath import DataPath, PathInfo, DataPathType
from .GrokError import GrokError
from .GrokWarning import GrokWarning
from .GrokNsec import GrokNsec
from .GrokCovering import GrokCovering

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
    "opt_out",
    "closest_encloser",
    "closest_encloser_digest",
    "next_closest_encloser",
    "next_closest_encloser_hash",
    "wildcard",
    "wildcard_hash",
    "status",
    "ns_names",
    "query_options",
    "nsec3",
    "nsec",
    "next_closest_encloser_covering",
    "servers",
    "warnings",
    "errors",
    "sname_nsec_match",
    "sname_hash",
    "closest_encloser_hash",
    "wildcard_covering",
    "sname_covering",
    "wildcard_nsec_match",
}


class GrokInsecurityProof(
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
        self.opt_out = json_data.get("opt_out")
        self.closest_enclose = json_data.get("closest_encloser")
        self.closest_encloser_digest = json_data.get("closest_encloser_digest")
        self.closest_encloser_hash = json_data.get("closest_encloser_hash")
        self.next_closest_encloser = json_data.get("next_closest_encloser")
        self.next_closest_encloser_hash = json_data.get("next_closest_encloser_hash")
        self.wildcard = json_data.get("wildcard")
        self.wilcard_hash = json_data.get("wildcard_hash")
        self.status = json_data.get("status")
        self.sname_nsec_match = json_data.get("sname_nsec_match")
        self.sname_hash = json_data.get("sname_hash")
        self.wildcard_nsec_match = json_data.get("wildcard_nsec_match")

        self.nsec: List[GrokNsec] = []
        self.nsec3: List[GrokNsec] = []

        if "nsec3" in json_data:
            for index, n in enumerate(json_data["nsec3"]):
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

        if "nsec" in json_data:
            for index, n in enumerate(json_data["nsec"]):
                self.nsec3.append(
                    GrokNsec(
                        n,
                        path_info=self.new_path(
                            added_path="nsec",
                            data_type=DataPathType.list,
                            list_index=index,
                        ),
                    )
                )

        self.wildcard_covering: GrokCovering = None
        if "wildcard_covering" in json_data:
            self.wildcard_covering = GrokCovering(
                json_data["wildcard_covering"],
                path_info=self.new_path(
                    added_path="wildcard_covering", data_type=DataPathType.dict
                ),
            )

        self.next_closest_encloser_covering: GrokCovering = None
        if "next_closest_encloser_covering" in json_data:
            self.next_closest_encloser_covering = GrokCovering(
                json_data["next_closest_encloser_covering"],
                path_info=self.new_path(
                    added_path="next_closest_encloser_covering",
                    data_type=DataPathType.dict,
                ),
            )

        self.sname_covering: GrokCovering = None
        if "sname_covering" in json_data:
            self.sname_covering = GrokCovering(
                json_data["sname_covering"],
                path_info=self.new_path(
                    added_path="sname_covering", data_type=DataPathType.dict
                ),
            )

        GrokDebugKeySet.__init__(
            self, debug_set, list(json_data.keys()), self.__class__.__name__
        )
