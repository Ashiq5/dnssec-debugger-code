from enum import Enum

from .GrokError import GrokError
from .GrokWarning import GrokWarning
from .GrokPath import DataPath, PathInfo, DataPathType


class GrokErrorList:
    errors: list[GrokError] = None

    def __init__(self, json_data: dict):
        self.errors = []
        for index, err in enumerate(json_data.get("errors", [])):
            self.errors.append(
                GrokError(
                    err,
                    path_info=self.new_path(
                        added_path="", data_type=DataPathType.list, list_index=index
                    ),
                )
            )

    def get_errors(self) -> list[GrokError]:
        """
        Collect errors from all attributes of the class that inherit from GrokError.
        This method will check attributes and, if they inherit from GrokError, it will add their errors.
        """
        # Initialize the list of errors
        all_errors = [] + self.errors
        # Iterate over all attributes of the class
        for attr_name, attr_value in self.__dict__.items():
            # If the attribute is a list, iterate over the items in the list
            if isinstance(attr_value, list):
                for err in attr_value:
                    if isinstance(err, GrokError):
                        all_errors.append(err)
                    if isinstance(err, GrokErrorList):
                        all_errors += err.get_errors()

            elif isinstance(attr_value, GrokErrorList):
                all_errors += attr_value.get_errors()

            elif isinstance(attr_value, GrokError):
                # If the attribute itself is an instance of GrokError
                all_errors.append(attr_value)

        return all_errors


class GrokWarningList:
    warnings: list[GrokWarning] = None

    def __init__(self, json_data):
        self.warnings = []
        for warning in json_data.get("warnings", []):
            self.warnings.append(GrokWarning(json_data=warning))


class GrokServersList:
    servers: list[str] = None

    def __init__(self, json_data):
        self.servers = []
        for server in json_data.get("servers", []):
            self.servers.append(server)


class GrokQueryOptionsList:
    query_options: list[str] = None

    def __init__(self, json_data):
        query_options = []
        for queryOption in json_data.get("queryOptions", []):
            self.query_options.append(queryOption)


class GrokNsNamesList:
    ns_names: list[str] = None

    def __init__(self, json_data):
        self.ns_names = []
        for nsName in json_data.get("names", []):
            self.ns_names.append(nsName)


class GrokContainsErrors:
    def __init__(self):
        pass
