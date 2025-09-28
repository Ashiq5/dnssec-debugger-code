from .Meta import GrokDebugKeySet
from .GrokPath import DataPath, PathInfo, DataPathType

from typing import List

debug_set = {"description", "code", "servers", "query_options"}


class GrokError(GrokDebugKeySet, DataPath):
    def __init__(self, json_data: dict, path_info: PathInfo):
        DataPath.__init__(self, path_info)
        self.description = json_data["description"]
        self.code = json_data["code"]
        self.server = json_data.get("servers")
        self.query_options = json_data.get("queries")

        # Call To Check if we are not missing keys in the dataset.
        super().__init__(debug_set, list(json_data.keys()), self.__class__.__name__)

    def json(self):
        return {
            "description": self.description,
            "code": self.code,
            "path": self.path.parent_path,
        }
