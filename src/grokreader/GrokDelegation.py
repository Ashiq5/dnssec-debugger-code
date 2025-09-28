from typing import List
from .Meta import GrokDebugKeySet
from .GrokPath import DataPath, PathInfo, DataPathType
from .GrokError import GrokError
from .GrokWarning import GrokWarning
from .GrokDS import GrokDS
from .GrokInsecurityProof import GrokInsecurityProof
from .GrokCommons import GrokErrorList, GrokWarningList


debug_set = {"status", "ds", "errors", "insecurity_proof", "warnings"}


class GrokDelegation(GrokDebugKeySet, GrokErrorList, GrokWarningList, DataPath):
    def __init__(self, json_data: dict, path_info: PathInfo):
        DataPath.__init__(self, path_info)
        GrokErrorList.__init__(self, json_data=json_data)
        GrokWarningList.__init__(self, json_data=json_data)

        self.ds: List[GrokDS] = []
        self.status = json_data.get("status", None)

        self.insecurity_proof: List[GrokInsecurityProof] = []

        if json_data.get("ds"):
            for index, d in enumerate(json_data["ds"]):
                self.ds.append(
                    GrokDS(
                        d,
                        path_info=self.new_path(
                            added_path="ds",
                            data_type=DataPathType.list,
                            list_index=index,
                        ),
                    )
                )

        if json_data.get("insecurity_proof"):
            for index, ins in enumerate(json_data["insecurity_proof"]):
                self.insecurity_proof.append(
                    GrokInsecurityProof(
                        ins,
                        path_info=self.new_path(
                            added_path="insecurity_proof",
                            data_type=DataPathType.list,
                            list_index=index,
                        ),
                    )
                )

        GrokDebugKeySet.__init__(
            self, debug_set, list(json_data.keys()), self.__class__.__name__
        )

    def get_ds_map(self):
        return [ds.get_ds_info() for ds in self.ds]
