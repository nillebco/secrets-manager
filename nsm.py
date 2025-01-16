from fire import Fire
import os
import json
import socket
from datetime import datetime
import sys
import subprocess
from typing import Optional


class NillebCoSecretsManager:
    def __init__(self):
        self.conf_file = os.path.expanduser("~/.nsm.json")
        self.conf = {}
        if os.path.exists(self.conf_file):
            with open(self.conf_file, "r") as f:
                self.conf = json.load(f)

    def set_org(self, org: str):
        self.conf["org"] = org
        with open(self.conf_file, "w") as f:
            json.dump(self.conf, f)

    def get_bws_access_token(self):
        host_name = socket.gethostname()
        host_name = host_name.replace(".local", "")
        suffix = datetime.now().year
        secret_name = f"bws-{self.conf['org']}-{host_name}-{suffix}"
        secret_value = os.popen(
            f"security find-generic-password -a none -s {secret_name} -w"
        ).read()
        return secret_value.rstrip()

    def wrap_bws(self, *args, **kwargs):
        args = [f'"{arg}"' for arg in sys.argv[2:]]
        cmd = f"bws --access-token {self.get_bws_access_token()} {' '.join(args)}"
        try:
            subprocess.run(cmd, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            sys.exit(e.returncode)

    def _organizations(self):
        cmd = f"bws --access-token {self.get_bws_access_token()} project list"
        result = subprocess.run(
            cmd, shell=True, check=True, capture_output=True, text=True
        )
        projects = json.loads(result.stdout)
        organizations = list(set([project["organizationId"] for project in projects]))
        return organizations

    def organizations(self):
        for organization in self._organizations():
            print(f"{organization}")

    def _projects(self):
        cmd = f"bws --access-token {self.get_bws_access_token()} project list"
        result = subprocess.run(
            cmd, shell=True, check=True, capture_output=True, text=True
        )
        projects = json.loads(result.stdout)
        return projects

    def projects(self):
        projects = self._projects()
        for project in projects:
            print(
                f"{project['name']} ({project['id']}) (orgId: {project['organizationId']})"
            )

    def _secrets(self):
        cmd = f"bws --access-token {self.get_bws_access_token()} secret list"
        result = subprocess.run(
            cmd, shell=True, check=True, capture_output=True, text=True
        )
        secrets = json.loads(result.stdout)
        return secrets

    def secrets(self):
        for secret in self._secrets():
            print(
                f"{secret['key']} ({secret['id']}) (projectId: {secret['projectId']})"
            )

    def secret_value(self, name: str):
        secrets = self._secrets()
        for secret in secrets:
            if secret["key"] == name:
                return secret["value"]
        return None

if __name__ == "__main__":
    Fire(NillebCoSecretsManager, name="nsm")

# use the `security cli to retrieve the access token to the bitwarden secrets manager
# security find-generic-password -a <account_name> -s <service_name> -w
# security find-generic-password -a none -s bws-adc-openarms-2025 -w

# update the access token in the os keychain
# security add-generic-password -a <account_name> -s <service_name> -w <secret_value>
