from .Meta import GrokDebugKeySet

debug_set = {"code", "description", "servers", "query_options"}


class GrokWarning(GrokDebugKeySet):
    def __init__(self, json_data):
        self.description = json_data.get("description")
        self.code = json_data.get("code")
        self.servers = json_data.get("servers")
        self.query_options = json_data.get("query_options")

        super().__init__(debug_set, list(json_data.keys()), self.__class__.__name__)
