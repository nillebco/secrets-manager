from fire import Fire
import os
import sys
from bitwarden_client import BitwardenClient
from google_secrets_manager import GoogleSecretsManager
from configuration import Configuration
from functools import wraps
from typing import Callable, TypeVar, Any, Optional

T = TypeVar("T")


def require_provider(f: Callable[..., T]) -> Callable[..., T]:
    @wraps(f)
    def wrapper(self: "BaseManager", *args: Any, **kwargs: Any) -> T:
        if not self.current_client:
            print(
                "Error: Provider not set. Please run 'nsm provider use <name>' first."
            )
            sys.exit(1)
        return f(self, *args, **kwargs)

    return wrapper


class BaseManager:
    """Base class for all manager classes providing configuration and client management."""
    def __init__(self, conf_file: Optional[str] = None, config: Optional[Configuration] = None):
        """
        Initialize the base manager.
        
        Args:
            conf_file: Path to the configuration file. If not provided, uses default.
            config: Configuration object. If provided, uses this instead of loading from file.
        """
        if config:
            self.config = config
            self.conf_file = conf_file or os.path.expanduser("~/.nsm.json")
        else:
            self.conf_file = conf_file or os.path.expanduser("~/.nsm.json")
            self.config = Configuration.load(self.conf_file)
        self.current_client = None
        self._initialize_client()

    def _initialize_client(self) -> None:
        """Initialize the appropriate secrets manager client based on configuration."""
        provider_config = self.config.get_current_provider()
        if not provider_config:
            return

        if provider_config.type == "bitwarden" and provider_config.org:
            self.current_client = BitwardenClient(provider_config.org)
        elif provider_config.type == "google":
            self.current_client = GoogleSecretsManager()


class ProviderCommands(BaseManager):
    def add(self, name: str, provider: str, identifier: Optional[str] = None) -> None:
        """
        Add a new provider configuration.

        Args:
            name: Name to identify this provider configuration
            provider: Either 'bitwarden' or 'google'
            identifier: Organization ID for Bitwarden, or Project ID for Google. Optional for Google.
        """
        if provider not in ["bitwarden", "google"]:
            print("Error: Provider must be either 'bitwarden' or 'google'")
            sys.exit(1)

        # Check if a Google provider already exists
        if provider == "google":
            existing_google = [
                name for name, p in self.config.providers.items() 
                if p.type == "google"
            ]
            if existing_google:
                print(f"Error: A Google provider already exists: {existing_google[0]}")
                print("Only one Google provider is allowed.")
                sys.exit(1)

        if provider == "bitwarden":
            if not identifier:
                print("Error: Organization ID is required for Bitwarden provider")
                sys.exit(1)
            self.config.add_provider(name, provider, org=identifier)
        else:  # google
            self.config.add_provider(name, provider, project_id=identifier)

        if not self.config.current_provider:
            self.config.current_provider = name

        self.config.save(self.conf_file)
        print(f"Provider '{name}' added successfully")

    def use(self, name: str) -> None:
        """
        Switch to using a specific provider configuration.

        Args:
            name: Name of the provider configuration to use
        """
        if name not in self.config.providers:
            print(f"Error: Provider '{name}' not found")
            sys.exit(1)

        self.config.current_provider = name
        self.config.save(self.conf_file)
        self._initialize_client()
        print(f"Now using provider '{name}'")

    def list(self) -> None:
        """List all configured providers."""
        if not self.config.providers:
            print("No providers configured")
            return

        for name, provider in self.config.providers.items():
            current = "*" if name == self.config.current_provider else " "
            if provider.type == "bitwarden":
                print(f"{current} {name}: bitwarden (org: {provider.org})")
            else:
                print(f"{current} {name}: google (project: {provider.project_id})")


class SecretsCommands(BaseManager):
    @require_provider
    def list(self, project_id: Optional[str] = None) -> None:
        """
        List all secrets in the current provider.

        Args:
            project_id: Optional project ID to filter secrets by (works with both providers)
        """
        for secret in self.current_client.list_secrets(project_id):
            if isinstance(self.current_client, BitwardenClient):
                print(
                    f"{secret['key']} ({secret['id']}) (projectId: {secret['projectId']})"
                )
            else:
                print(
                    f"{secret['name']} (created: {secret['create_time']}) (projectId: {secret['project_id']})"
                )

    @require_provider
    def get(self, name: str, project_id: Optional[str] = None) -> Optional[str]:
        """
        Get the value of a secret.

        Args:
            name: The name of the secret to retrieve
            project_id: Optional project ID or name to get the secret from
        """
        value = self.current_client.get_secret(name, project_id)
        if value is None:
            print(f"Secret '{name}' not found")
            return None
        return value

    @require_provider
    def set(self, name: str, value: str, metadata: Optional[dict] = None) -> None:
        """
        Store a secret in the current provider.

        Args:
            name: The name of the secret to store
            value: The value to store
            metadata: Optional metadata to store with the secret
        """
        self.current_client.store_secret(name, value, metadata)
        print(f"Secret '{name}' stored successfully")

    @require_provider
    def delete(self, name: str) -> None:
        """
        Delete a secret from the current provider.

        Args:
            name: The name of the secret to delete
        """
        if self.current_client.delete_secret(name):
            print(f"Secret '{name}' deleted successfully")
        else:
            print(f"Secret '{name}' not found")


class NillebCoSecretsManager(BaseManager):
    @require_provider
    def projects(self) -> None:
        """List projects."""
        projects = self.current_client.list_projects()
        for project in projects:
            print(f"{project.name} ({project.id}) (orgId: {project.organization_id})")

    @require_provider
    def organizations(self) -> None:
        """List organizations (Bitwarden-specific)."""
        for organization in self.current_client.list_organizations():
            print(f"{organization.name} ({organization.id})")

    def provider(self) -> ProviderCommands:
        return ProviderCommands(config=self.config, conf_file=self.conf_file)

    def secret(self) -> SecretsCommands:
        return SecretsCommands(config=self.config, conf_file=self.conf_file)

    # Bitwarden-specific commands
    def set_access_token(self, token: str) -> None:
        """Set the Bitwarden access token (Bitwarden-specific)."""
        if not isinstance(self.current_client, BitwardenClient):
            print("Error: This command is only available for Bitwarden")
            sys.exit(1)
        self.current_client.set_access_token(token)
        print("Access token stored successfully")


def main():
    Fire(NillebCoSecretsManager, name="nsm")


if __name__ == "__main__":
    main()

# use the `security cli to retrieve the access token to the bitwarden secrets manager
# security find-generic-password -a <account_name> -s <service_name> -w
# security find-generic-password -a none -s bws-adc-openarms-2025 -w

# update the access token in the os keychain
# security add-generic-password -a <account_name> -s <service_name> -w <secret_value>
