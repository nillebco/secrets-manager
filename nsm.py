from fire import Fire
import os
import sys
from bitwarden_client import BitwardenClient
from google_secrets_manager import GoogleSecretsManager
from configuration import Configuration
from functools import wraps
from typing import Callable, TypeVar, Any, Optional, Union

T = TypeVar('T')

def require_provider(f: Callable[..., T]) -> Callable[..., T]:
    @wraps(f)
    def wrapper(self: 'NillebCoSecretsManager', *args: Any, **kwargs: Any) -> T:
        if not self.current_client:
            print("Error: Provider not set. Please run 'nsm set_provider <bitwarden|google>' first.")
            sys.exit(1)
        return f(self, *args, **kwargs)
    return wrapper


class NillebCoSecretsManager:
    def __init__(self):
        self.conf_file = os.path.expanduser("~/.nsm.json")
        self.config = Configuration.load(self.conf_file)
        print(self.config)
        self.current_client = None
        self._initialize_client()

    def _initialize_client(self) -> None:
        """Initialize the appropriate secrets manager client based on configuration."""
        if not self.config.provider:
            return
            
        if self.config.provider == "bitwarden" and self.config.org:
            self.current_client = BitwardenClient(self.config.org)
        elif self.config.provider == "google" and self.config.project_id:
            self.current_client = GoogleSecretsManager(self.config.project_id)

    def set_provider(self, identifier: str, provider: str) -> None:
        """
        Set the secrets manager provider and its identifier.
        
        Args:
            provider: Either 'bitwarden' or 'google'
            identifier: Organization ID for Bitwarden, or Project ID for Google
        """
        if provider not in ["bitwarden", "google"]:
            print("Error: Provider must be either 'bitwarden' or 'google'")
            sys.exit(1)
            
        self.config.provider = provider
        
        if provider == "bitwarden":
            self.config.org = identifier
            if identifier:
                self.current_client = BitwardenClient(identifier)
        else:  # google
            self.config.project_id = identifier
            if identifier:
                self.current_client = GoogleSecretsManager(identifier)
                
        self.config.save(self.conf_file)

    @require_provider
    def secrets(self, project_id: Optional[str] = None) -> None:
        """
        List all secrets in the current provider.
        
        Args:
            project_id: Optional project ID to filter secrets by (works with both providers)
        """
        for secret in self.current_client.list_secrets(project_id):
            if isinstance(self.current_client, BitwardenClient):
                print(f"{secret['key']} ({secret['id']}) (projectId: {secret['projectId']})")
            else:
                print(f"{secret['name']} (created: {secret['create_time']}) (projectId: {secret['project_id']})")

    @require_provider
    def secret_value(self, name: str) -> Optional[str]:
        """Get the value of a secret."""
        return self.current_client.get_secret(name)

    @require_provider
    def store_secret(self, name: str, value: str, metadata: Optional[dict] = None) -> None:
        """Store a secret in the current provider."""
        self.current_client.store_secret(name, value, metadata)
        print(f"Secret '{name}' stored successfully")

    @require_provider
    def delete_secret(self, name: str) -> None:
        """Delete a secret from the current provider."""
        if self.current_client.delete_secret(name):
            print(f"Secret '{name}' deleted successfully")
        else:
            print(f"Secret '{name}' not found")

    # Bitwarden-specific commands
    def set_access_token(self, token: str) -> None:
        """Set the Bitwarden access token (Bitwarden-specific)."""
        if not isinstance(self.current_client, BitwardenClient):
            print("Error: This command is only available for Bitwarden")
            sys.exit(1)
        self.current_client.set_access_token(token)
        print("Access token stored successfully")

    @require_provider
    def organizations(self) -> None:
        """List organizations (Bitwarden-specific)."""
        if not isinstance(self.current_client, BitwardenClient):
            print("Error: This command is only available for Bitwarden")
            sys.exit(1)
        for organization in self.current_client.get_organizations():
            print(f"{organization}")

    @require_provider
    def projects(self) -> None:
        """List projects (Bitwarden-specific)."""
        if not isinstance(self.current_client, BitwardenClient):
            print("Error: This command is only available for Bitwarden")
            sys.exit(1)
        projects = self.current_client.get_projects()
        for project in projects:
            print(f"{project['name']} ({project['id']}) (orgId: {project['organizationId']})")


def main():
    Fire(NillebCoSecretsManager, name="nsm")

if __name__ == "__main__":
    main()

# use the `security cli to retrieve the access token to the bitwarden secrets manager
# security find-generic-password -a <account_name> -s <service_name> -w
# security find-generic-password -a none -s bws-adc-openarms-2025 -w

# update the access token in the os keychain
# security add-generic-password -a <account_name> -s <service_name> -w <secret_value>
