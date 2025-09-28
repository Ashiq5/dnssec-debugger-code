from enum import Enum


class DataPathType(Enum):
    dict = 0
    list = 1


class PathInfo:
    def __init__(self, parent_path, current_type: DataPathType, depth: int):
        self.parent_path = parent_path
        self.current_type = current_type
        self.depth = depth

    def is_in_delegeation(self, domain=""):
        if domain != "" and f"{domain}/IN/DS" in self.parent_path:
            return True

        return "delegation|insecurity_proof" in self.parent_path


class DataPath:
    path = None

    def __init__(self, path: PathInfo):
        self.path = path

    def get_path(self):
        return self.path

    def new_path(
        self, added_path: str, data_type: DataPathType, list_index=-1
    ) -> PathInfo:
        if data_type.value == DataPathType.dict.value:
            new = self.path.parent_path + f"|{added_path}"

        elif data_type.value == DataPathType.list.value:
            if list_index == -1:
                raise Exception("List index not provided during the list stuff")
            new = self.path.parent_path + f"|{added_path}[{list_index}]"

        else:
            raise Exception(f"path type {data_type} is not supported")

        return PathInfo(
            parent_path=new, current_type=data_type, depth=self.path.depth + 1
        )
