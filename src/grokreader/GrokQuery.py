from typing import List
from .Meta import GrokDebugKeySet
from .GrokPath import DataPath, PathInfo, DataPathType
from .GrokAnswer import GrokAnswer
from .DnsStuff import DnsError, DnsWaring
from .GrokNoData import GrokNxDomain, GrokNoData
from .GrokError import GrokError

debug_set = {"answer", "error", "nodata", "nxdomain", "warning"}


class GrokQuery(GrokDebugKeySet, DataPath):
    def __init__(self, json_data: dict, qname: str, path_info: PathInfo):
        DataPath.__init__(self, path_info)

        self.qname = qname
        self.answers: List[GrokAnswer] = []
        self.error: List[DnsError] = []
        self.warning: List[DnsWaring] = []
        self.nodata: List[GrokNoData] = []
        self.nxdomain: List[GrokNxDomain] = []

        for index, answer in enumerate(json_data.get("answer", [])):
            self.answers.append(
                GrokAnswer(
                    json_data=answer,
                    path_info=self.new_path(
                        added_path="answer",
                        data_type=DataPathType.list,
                        list_index=index,
                    ),
                )
            )

        for error in json_data.get("error", []):
            self.error.append(DnsError(json_data=error))

        for index, nodata in enumerate(json_data.get("nodata", [])):
            self.nodata.append(
                GrokNoData(
                    json_data=nodata,
                    path_info=self.new_path(
                        added_path="nodata",
                        data_type=DataPathType.list,
                        list_index=index,
                    ),
                )
            )

        for index, nxdomain in enumerate(json_data.get("nxdomain", [])):
            self.nxdomain.append(
                GrokNxDomain(
                    json_data=nxdomain,
                    path_info=self.new_path(
                        added_path="nxdomain",
                        data_type=DataPathType.list,
                        list_index=index,
                    ),
                )
            )

        for warning in json_data.get("warning", []):
            self.warning.append(DnsWaring(json_data=warning))

        super().__init__(debug_set, list(json_data.keys()), self.__class__.__name__)

    def get_errors(self) -> list[GrokError]:
        res = []
        for data in [self.answers, self.nodata, self.nxdomain]:
            for d in data:
                res += d.get_errors()

        return res

    def get_denial_of_existence_parameters(self):
        for denial_of_existence in self.nodata + self.nxdomain:
            params = denial_of_existence.get_denial_of_existence_parameters()
            if params is not None:
                return params

        return None
