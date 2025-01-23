from fire import Fire
import os
import sys
from bitwarden_client import BitwardenClient
from configuration import Configuration
from functools import wraps
from typing import Callable, TypeVar, Any

T = TypeVar('T')

def require_org(f: Callable[..., T]) -> Callable[..., T]:
    @wraps(f)
    def wrapper(self: 'NillebCoSecretsManager', *args: Any, **kwargs: Any) -> T:
        if not self.bw_client:
            print("Error: Organization not set. Please run 'nsm set_org <org>' first.")
            sys.exit(1)
        return f(self, *args, **kwargs)
    return wrapper


class NillebCoSecretsManager:
    def __init__(self):
        self.conf_file = os.path.expanduser("~/.nsm.json")
        self.config = Configuration.load(self.conf_file)
        self.bw_client = None
        if self.config.org:
            self.bw_client = BitwardenClient(self.config.org)

    def set_org(self, org: str):
        self.config.org = org
        self.config.save(self.conf_file)
        self.bw_client = BitwardenClient(org)

    @require_org
    def wrap_bws(self, *args, **kwargs):
        try:
            self.bw_client.execute_command(*sys.argv[2:])
        except Exception:
            sys.exit(1)

    @require_org
    def organizations(self):
        for organization in self.bw_client.get_organizations():
            print(f"{organization}")

    @require_org
    def projects(self):
        projects = self.bw_client.get_projects()
        for project in projects:
            print(
                f"{project['name']} ({project['id']}) (orgId: {project['organizationId']})"
            )

    @require_org
    def secrets(self):
        for secret in self.bw_client.list_secrets():
            print(
                f"{secret['key']} ({secret['id']}) (projectId: {secret['projectId']})"
            )

    @require_org
    def secret_value(self, name: str):
        return self.bw_client.get_secret(name)

    @require_org
    def store_secret(self, name: str, value: str):
        """Store a secret in the secrets manager."""
        return self.bw_client.store_secret(name, value)

    @require_org
    def delete_secret(self, name: str):
        """Delete a secret from the secrets manager."""
        if self.bw_client.delete_secret(name):
            print(f"Secret '{name}' deleted successfully")
        else:
            print(f"Secret '{name}' not found")

    @require_org
    def set_access_token(self, token: str):
        """
        Set the Bitwarden access token in the system keychain.
        
        Args:
            token: The access token to store
        """
        self.bw_client.set_access_token(token)
        print("Access token stored successfully")


if __name__ == "__main__":
    Fire(NillebCoSecretsManager, name="nsm")

# use the `security cli to retrieve the access token to the bitwarden secrets manager
# security find-generic-password -a <account_name> -s <service_name> -w
# security find-generic-password -a none -s bws-adc-openarms-2025 -w

# update the access token in the os keychain
# security add-generic-password -a <account_name> -s <service_name> -w <secret_value>
