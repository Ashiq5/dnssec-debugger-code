from typing import List
from .Meta import GrokDebugKeySet
from .GrokPath import DataPath, PathInfo, DataPathType
from .GrokServerInfo import GrokServerInfo
from .GrokCommons import GrokErrorList, GrokWarningList


debug_set = {"servers", "errors", "warnings"}


class GrokZone(GrokDebugKeySet, GrokErrorList, GrokWarningList, DataPath):
    def __init__(self, json_data, path_info: PathInfo):
        DataPath.__init__(self, path_info)
        GrokErrorList.__init__(self, json_data=json_data)
        GrokWarningList.__init__(self, json_data=json_data)

        self.servers: List[GrokServerInfo] = []

        for index, server in enumerate(json_data.get("servers", [])):
            self.servers.append(
                GrokServerInfo(
                    server_name=server,
                    json_data=json_data["servers"][server],
                    path_info=self.new_path(
                        added_path="servers",
                        data_type=DataPathType.list,
                        list_index=index,
                    ),
                )
            )

        GrokDebugKeySet.__init__(
            self, debug_set, list(json_data.keys()), self.__class__.__name__
        )
