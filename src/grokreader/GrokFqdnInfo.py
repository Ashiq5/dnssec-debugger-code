import json
from typing import List
from .Meta import GrokDebugKeySet
from .GrokPath import DataPath, PathInfo, DataPathType
from .GrokZone import GrokZone
from .GrokQuery import GrokQuery
from .GrokDnsKey import GrokDnsKey
from .GrokDelegation import GrokDelegation
from .GrokError import GrokError

debug_set = {"zone", "status", "queries", "dnskey", "delegation"}


class GrokFqdnInfo(GrokDebugKeySet, DataPath):

    def __init__(self, json_data, fqdn: str, path_info: PathInfo) -> None:
        DataPath.__init__(self, path_info)
        self.zone_info: GrokZone = None
        self.status: str = None
        self.delegation: GrokDelegation = None
        self.dnskey: List[GrokDnsKey] = []
        self.queries: List[GrokQuery] = []
        self.name = fqdn

        if "zone" in json_data:

            self.zone_info = GrokZone(
                json_data["zone"],
                path_info=self.new_path(added_path="zone", data_type=DataPathType.dict),
            )

        if "status" in json_data:
            self.status = json_data["status"]

        if "delegation" in json_data:
            self.delegation = GrokDelegation(
                json_data["delegation"],
                path_info=self.new_path(
                    added_path="delegation", data_type=DataPathType.dict
                ),
            )

        if "dnskey" in json_data:
            for index, k in enumerate(json_data["dnskey"]):
                self.dnskey.append(
                    GrokDnsKey(
                        k,
                        path_info=self.new_path(
                            added_path="dnskey",
                            data_type=DataPathType.list,
                            list_index=index,
                        ),
                    )
                )

        if "queries" in json_data:
            for index, query in enumerate(json_data["queries"].keys()):
                self.queries.append(
                    GrokQuery(
                        json_data["queries"][query],
                        query,
                        path_info=self.new_path(
                            added_path=f"queries|.{query}", data_type=DataPathType.dict
                        ),
                    )
                )

        super().__init__(debug_set, list(json_data.keys()), self.__class__.__name__)

    def get_ds_map(self):
        if self.delegation is None:
            return None

        res = []
        unique_set = set()

        for e in self.delegation.get_ds_map():
            json_e = json.dumps(e)
            if json_e not in unique_set:
                unique_set.add(json_e)
                res.append(e)

        return res

    def get_key_map(self):
        return [dnskey.get_info() for dnskey in self.dnskey]

    def get_errors(self) -> list[GrokError]:
        res: list[GrokError] = []
        if self.zone_info is not None:
            try:
                res += self.zone_info.get_errors()
            except Exception as e:
                raise e

        if self.delegation is not None:
            res += self.delegation.get_errors()

        for dnskey in self.dnskey:
            res += dnskey.get_errors()

        for query in self.queries:
            res += query.get_errors()

        return res

    def get_denial_of_existence_parameters(self):
        if len(self.queries) != 0:

            for grok_query in self.queries:
                doe_param = grok_query.get_denial_of_existence_parameters()
                if doe_param is None:
                    continue
                return doe_param

        else:
            raise Exception("Should not happen")

        return None
