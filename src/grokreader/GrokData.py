import json


from .GrokFqdnInfo import GrokFqdnInfo
from typing import List

from .GrokError import GrokError
from .Meta import is_root_or_tld
from .GrokPath import DataPath, PathInfo, DataPathType


class GrokData(DataPath):
    def __init__(self, line, homemade_measurement=False):
        DataPath.__init__(
            self, PathInfo(parent_path="", current_type=DataPathType.dict, depth=0)
        )

        self.line = line
        self.GrokFqdnInfos: List[GrokFqdnInfo] = []

        """       
       ---
       This is the structure of our specific file measurements.
       However the following for code release we take into consideration the it"s only the dnsviz grok output
       --- 
       """

        if homemade_measurement:
            try:
                self.js = json.loads(self.line)
                self.id = self.js[0]
                self.status_code = int(self.js[1][0])

                if self.status_code != 200:
                    return
            except:
                self.json_data = None

            self.json_data = self.js[1][1]

        else:
            try:
                self.json_data = json.loads(self.line)
            except:
                self.json_data = None

        for fqdn in self.json_data.keys():
            self.GrokFqdnInfos.append(
                GrokFqdnInfo(
                    json_data=self.json_data[fqdn],
                    fqdn=fqdn,
                    path_info=self.new_path(
                        added_path=str(fqdn), data_type=DataPathType.dict
                    ),
                )
            )

    def get_key_map(self):
        res = dict()
        for fqdn in self.GrokFqdnInfos:
            res[fqdn.name] = fqdn.get_key_map()

        return res

    def get_ds(self):
        res = dict()
        for fqdn in self.GrokFqdnInfos:
            res[fqdn.name] = fqdn.get_ds_map()

        return res

    def get_errors(self) -> list[GrokError]:
        res: list[GrokError] = []
        for fqdn in self.GrokFqdnInfos:
            if is_root_or_tld(fqdn.name):
                continue
            res += fqdn.get_errors()
        return res

    def error_set(self):
        return set([e.code for e in self.get_errors()])

    def error_list_description(self):
        return "".join(
            [f" --> {e.code} : {e.get_path().parent_path}\n" for e in self.get_errors()]
        )

    def dom2err(self):
        res = dict()
        for fqdn in self.GrokFqdnInfos:
            domain = fqdn.name.lower().strip(".")
            if is_root_or_tld(domain):
                continue
            errors_fqdn = fqdn.get_errors()
            if len(errors_fqdn) > 1:
                res[domain] = []
                err_set = set()
                for error in errors_fqdn:
                    current_error = error.json()
                    current_error_str = json.dumps(current_error)
                    if current_error_str not in err_set:
                        err_set.add(current_error_str)
                        res[domain].append(error.json())
        return res

    def identify_zone_name(self):
        sort_list = sorted(
            [fqdn.name for fqdn in self.GrokFqdnInfos if fqdn.zone_info is not None],
            key=lambda x: len(x),
            reverse=True,
        )
        if len(sort_list) == 0:
            return None

        else:
            return sort_list[0]

    def identify_parent_zone(self):
        zone_name = self.identify_zone_name()

        sort_list = sorted(
            [
                fqdn.name
                for fqdn in self.GrokFqdnInfos
                if (
                    fqdn.zone_info is not None
                    and fqdn.name != zone_name
                    and not fqdn.name.endswith(zone_name)
                    and zone_name.endswith(fqdn.name)
                )
            ],
            key=lambda x: len(x),
            reverse=True,
        )
        if len(sort_list) == 0:
            return None

        else:
            return sort_list[0]

    def get_errcodes_for_zone(self, zone):
        res = set()
        for fqdn in self.GrokFqdnInfos:
            if not fqdn.name.endswith(zone) or is_root_or_tld(fqdn.name):
                continue

            if fqdn.name == zone:
                fqdn_errors = fqdn.get_errors()
                for error in fqdn_errors:
                    if error.path.is_in_delegeation(fqdn.name):
                        continue
                    res.add(error.code)
            else:
                for error in fqdn.get_errors():

                    res.add(error.code)

        return res

    def get_fqdn_object_under_zone_name(self):
        res = []
        zone_name = self.identify_zone_name()
        for fqdn in self.GrokFqdnInfos:
            if fqdn.name.endswith(zone_name) and fqdn.name != zone_name:
                res.append(fqdn)
        return res

    def get_fqdn_object_of_zone_name(self) -> GrokFqdnInfo:
        zone_name = self.identify_zone_name()
        for fqdn in self.GrokFqdnInfos:
            if zone_name == fqdn.name:
                return fqdn

        return None

    def get_denial_of_existence_parameters(self):
        grok_fqdn = self.get_fqdn_object_of_zone_name()
        if grok_fqdn is None:
            raise Exception("Should not happen")

        return grok_fqdn.get_denial_of_existence_parameters()

    def get_signing_information(self):
        res = {"DNSKEY": set(), "OTHER": set()}
        have_cname = False
        grok_fqdn_zone = self.get_fqdn_object_of_zone_name()
        if grok_fqdn_zone is None:
            raise Exception("Should not happen")

        for grok_fqdn in [grok_fqdn_zone] + self.get_fqdn_object_under_zone_name():

            for query in grok_fqdn.queries:

                for answer in query.answers:

                    rtype = answer.type
                    if rtype not in ["DS", "DNSKEY"]:
                        for key in answer.get_rrsig_signers():
                            res["OTHER"].add(key)
                    if rtype == "DNSKEY":
                        for key in answer.get_rrsig_signers():
                            res["DNSKEY"].add(key)

        return res
