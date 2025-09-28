from .Meta import GrokDebugKeySet
from .GrokPath import DataPath, PathInfo, DataPathType


debug_set = {"covered_name", "nsec3_owner", "nsec_owner", "nsec_next", "nsec3_next"}


class GrokCovering(GrokDebugKeySet, DataPath):
    nsec_owner = None
    nsec_next = None

    def __init__(self, json_data: dict, path_info: PathInfo):

        DataPath.__init__(self, path_info)

        self.covered_name = json_data.get("covered_name")

        if "nsec3_owner" in json_data:
            self.nsec_owner = json_data.get("nsec3_owner")
        if "nsec_owner" in json_data:
            self.nsec_owner = json_data.get("nsec_owner")

        if "nsec3_next" in json_data:
            self.nsec_next = json_data.get("nsec3_next")
        if "nsec_next" in json_data:
            self.nsec_next = json_data.get("nsec_next")

        super().__init__(debug_set, list(json_data.keys()), self.__class__.__name__)
