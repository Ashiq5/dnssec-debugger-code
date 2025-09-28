from .Meta import IpString, GrokDebugKeySet
from .GrokPath import DataPath, PathInfo, DataPathType
from typing import List


debug_set = {"auth", "stealth", "glue"}


class GrokServerInfo(GrokDebugKeySet, DataPath):
    def __init__(self, json_data, server_name, path_info: PathInfo):
        DataPath.__init__(self, path_info)

        self.auth: List[IpString] = []
        self.stealth: List[IpString] = []
        self.glue: List[IpString] = []

        self.server_name = server_name

        for ip in json_data.get("auth", []):
            self.auth.append(IpString(ip))

        for ip in json_data.get("stealth", []):
            self.stealth.append(IpString(ip))

        for ip in json_data.get("glue", []):
            self.glue.append(IpString(ip))

        super().__init__(debug_set, list(json_data.keys()), self.__class__.__name__)

    def __str__(self):
        return f"name : {self.name}, glue : {self.glue}, auth : {self.auth}, stealth: {self.stealth}"
