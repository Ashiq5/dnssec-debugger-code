from config import *


class NamedConf:
    def __init__(self, domains, path=Path("/etc/bind/zones/")):
        self.domains = list(set(domains))
        self.path = path

    def add_domain(self, domain):
        if domain not in self.domains:
            self.domains.append(domain)

    def configuration(self, type="master"):
        if type == "master":
            res = """
//
// Generated Configuration here
//
"""

            for domain in self.domains:
                extension = ".signed"
                if "unsigned" in domain:
                    extension = ""
                res += (
                    f'zone "{domain}" IN {{\n'
                    f"      type master;\n"
                    f'      file "{self.path}/db.{domain.strip(".")}{extension}";\n'  # Removing the trailing dot
                    f"}};\n\n"
                )
        else:
            res = """
//
// Generated Configuration here
//
"""

            for domain in self.domains:
                extension = ".signed"
                if "unsigned" in domain:
                    extension = ""
                res += (
                    f'zone "{domain}" IN {{\n'
                    f"      type slave;\n"
                    f'      file "{self.path}/db.{domain.strip(".")}{extension}";\n'  # Removing the trailing dot
                    "      masters {" + f" {SERVER}" + "; };\n"
                    f"}};\n\n"
                )
        return res

    def write(self, filepath: Path, type):
        with open(filepath, "w") as f:
            f.write(self.configuration(type))

    def __str__(self):
        return self.configuration()
