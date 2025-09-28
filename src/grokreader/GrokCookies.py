from typing import List
from .Meta import GrokDebugKeySet


debug_set = {"request", "response"}


class GrokCookies(GrokDebugKeySet):
    def __init__(self, json_data: dict, origin):
        self.origin = origin
        self.request = json_data.get("request")
        self.response = json_data.get("response")

        super().__init__(debug_set, list(json_data.keys()), self.__class__.__name__)


class GrokCookiesList:
    def __init__(self, status: dict):
        self.status: List[GrokCookies] = []

        for k in status.keys():
            self.status.append(GrokCookies(status[k], k))
