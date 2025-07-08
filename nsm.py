from fire import Fire
import os
import sys
import json
import subprocess
from bitwarden_client import BitwardenClient
from google_secrets_manager import GoogleSecretsManager
from passbolt_client import PassboltClient
from configuration import Configuration
from functools import wraps
from typing import Callable, TypeVar, Any, Optional, Dict

T = TypeVar("T")


def require_provider(f: Callable[..., T]) -> Callable[..., T]:
    @wraps(f)
    def wrapper(self: "BaseManager", *args: Any, **kwargs: Any) -> T:
        if not self.current_client:
            # Try to initialize the client if not already done
            self._ensure_client_initialized()
            if not self.current_client:
                print(
                    "Error: Provider not set. Please run 'nsm provider use <name>' first."
                )
                sys.exit(1)
        return f(self, *args, **kwargs)

    return wrapper


class BaseManager:
    """Base class for all manager classes providing configuration and client management."""

    def __init__(
        self, conf_file: Optional[str] = None, config: Optional[Configuration] = None
    ):
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
            self._set_restrictive_permissions()
        self.current_client = None
        self._initialize_client()

    def _set_restrictive_permissions(self) -> None:
        """Set restrictive file permissions (600) on the configuration file."""
        if os.path.exists(self.conf_file):
            os.chmod(self.conf_file, 0o600)  # Read/write for owner only

    def _initialize_client(self) -> None:
        """Initialize the appropriate secrets manager client based on configuration."""
        provider_config = self.config.get_current_provider()
        if not provider_config:
            return

        if provider_config.type == "bitwarden":
            self.current_client = BitwardenClient(self.config.current_provider)
        elif provider_config.type == "google":
            self.current_client = GoogleSecretsManager()
        elif provider_config.type == "passbolt":
            self.current_client = PassboltClient(   
                organization_root_folder=provider_config.organization_root_folder,
            )
    
    def _ensure_client_initialized(self) -> None:
        """Ensure the client is initialized, especially for Passbolt."""
        if self.current_client:
            return
            
        provider_config = self.config.get_current_provider()
        if not provider_config:
            return
            


class ProviderCommands(BaseManager):
    def add(
        self,
        name: str,
        provider: str,
        server: Optional[str] = None,
        private_key_file: Optional[str] = None,
        organization_root_folder: Optional[str] = None,
    ) -> None:
        """
        Add a new provider configuration.

        Args:
            name: Name to identify this provider configuration
            provider: Either 'bitwarden', 'google', or 'passbolt'
            server: Server URL (required for passbolt)
            private_key_file: Path to private key file (required for passbolt)
            organization_root_folder: Optional root folder ID for passbolt (limits project listing)
        """
        if provider not in ["bitwarden", "google", "passbolt"]:
            print("Error: Provider must be either 'bitwarden', 'google', or 'passbolt'")
            sys.exit(1)

        # Check if a Google provider already exists
        if provider == "google":
            existing_google = [
                name for name, p in self.config.providers.items() if p.type == "google"
            ]
            if existing_google:
                print(f"Error: A Google provider already exists: {existing_google[0]}")
                print("Only one Google provider is allowed.")
                sys.exit(1)

        if provider == "bitwarden":
            self.config.add_provider(name, provider, org=name)
        elif provider == "google":
            self.config.add_provider(name, provider)
        elif provider == "passbolt":
            if not server or not private_key_file:
                print(
                    "Error: Passbolt provider requires both server and private_key_file arguments"
                )
                sys.exit(1)
            
            # Get passphrase for configuration
            passphrase = os.environ.get("PASSPHRASE")
            if not passphrase:
                import getpass
                passphrase = getpass.getpass("Enter Passbolt passphrase: ")
                if not passphrase:
                    print("Error: Passphrase is required for Passbolt provider")
                    sys.exit(1)
            
            # Configure Passbolt CLI
            try:
                cmd = [
                    "passbolt", "configure",
                    "--serverAddress", server,
                    "--userPassword", passphrase,
                    "--userPrivateKeyFile", private_key_file
                ]
                subprocess.run(cmd, check=True, capture_output=True, text=True)
                print("Passbolt CLI configured successfully")
            except subprocess.CalledProcessError as e:
                print(f"Error: Failed to configure Passbolt CLI: {e}")
                sys.exit(1)
            
            self.config.add_provider(
                name, provider, server=server, private_key_file=private_key_file, organization_root_folder=organization_root_folder
            )

        if not self.config.current_provider:
            self.config.current_provider = name

        self.config.save(self.conf_file)
        self._set_restrictive_permissions()
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
        self._set_restrictive_permissions()
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
                print(f"{current} {name}: bitwarden")
            elif provider.type == "google":
                print(f"{current} {name}: google")
            elif provider.type == "passbolt":
                print(f"{current} {name}: passbolt ({provider.server})")

    def remove(self, name: str) -> None:
        """
        Remove a specific provider configuration.

        Args:
            name: Name of the provider configuration to remove
        """
        if name not in self.config.providers:
            print(f"Error: Provider '{name}' not found")
            sys.exit(1)

        # If this is the current provider, clear the current provider
        if self.config.current_provider == name:
            self.config.current_provider = None

        del self.config.providers[name]
        self.config.save(self.conf_file)
        self._set_restrictive_permissions()
        print(f"Provider '{name}' removed successfully")

    def remove_all(self) -> None:
        """Remove all provider configurations."""
        if not self.config.providers:
            print("No providers configured")
            return

        provider_count = len(self.config.providers)
        self.config.remove_all_providers()
        self.config.save(self.conf_file)
        self._set_restrictive_permissions()
        print(f"Removed {provider_count} provider(s) successfully")


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
            elif isinstance(self.current_client, PassboltClient):
                print(
                    f"{secret['name']} ({secret['id']}) (folderId: {secret['folder_id']})"
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


class PassboltCommands(BaseManager):
    """Passbolt-specific plumbing commands."""
    
    @require_provider
    def list_folders(self, name: Optional[str] = None, parent_folder_id: Optional[str] = None) -> None:
        """
        List folders with optional filtering.
        
        Args:
            name: Optional name filter (e.g., "nillebco")
            parent_folder_id: Optional parent folder ID to filter by
        """
        if not isinstance(self.current_client, PassboltClient):
            print("Error: This command is only available for Passbolt")
            sys.exit(1)
        
        folders = self.current_client.list_folders(name, parent_folder_id)
        for folder in folders:
            print(f"{folder['name']} ({folder['id']}) (parent: {folder.get('folder_parent_id', 'root')})")
    
    @require_provider
    def get_or_create_folder(self, name: str, parent_folder_id: Optional[str] = None) -> None:
        """
        Get an existing folder or create it if it doesn't exist.
        
        Args:
            name: The name of the folder
            parent_folder_id: Optional parent folder ID
        """
        if not isinstance(self.current_client, PassboltClient):
            print("Error: This command is only available for Passbolt")
            sys.exit(1)
        
        folder = self.current_client.get_or_create_folder_by_name(name, parent_folder_id)
        print(f"Folder: {folder['name']} ({folder['id']})")


class ProjectSecretCommands(BaseManager):
    """Project secret management commands."""
    
    @require_provider
    def add(self, file: str) -> None:
        """
        Add a secret from a file to the current project.
        
        Args:
            file: Path to the file containing the secret
        """
        if not isinstance(self.current_client, PassboltClient):
            print("Error: Secret addition is currently only supported for Passbolt")
            sys.exit(1)
        
        # Read the .nsm.yaml file to get project_id
        project_id = self._get_project_id_from_yaml()
        if not project_id:
            print("Error: No project_id found in .nsm.yaml file")
            sys.exit(1)
        
        # Read the file content
        try:
            with open(file, 'r') as f:
                secret_value = f.read().strip()
        except FileNotFoundError:
            print(f"Error: File '{file}' not found")
            sys.exit(1)
        except Exception as e:
            print(f"Error: Failed to read file '{file}': {e}")
            sys.exit(1)
        
        # Create the secret in Passbolt
        try:
            cmd = ["create", "resource", "--name", file, "--password", secret_value, "-f", project_id]
            result = self.current_client._execute_json_command(*cmd)
            if result:
                secret_id = result[0]["id"]
                print(f"Secret '{file}' created with ID: {secret_id}")
                
                # Update .nsm.yaml file
                self._add_secret_to_yaml(file, secret_id)
            else:
                print("Error: Failed to create secret - no result returned")
                sys.exit(1)
        except Exception as e:
            print(f"Error: Failed to create secret: {e}")
            sys.exit(1)
    
    def _get_project_id_from_yaml(self) -> Optional[str]:
        """Get project_id from .nsm.yaml file."""
        try:
            import yaml
            with open(".nsm.yaml", 'r') as f:
                data = yaml.safe_load(f)
                return data.get('project_id')
        except FileNotFoundError:
            print("Error: .nsm.yaml file not found")
            return None
        except Exception as e:
            print(f"Error: Failed to read .nsm.yaml file: {e}")
            return None
    
    def _add_secret_to_yaml(self, file_name: str, secret_id: str) -> None:
        """Add a secret entry to .nsm.yaml file."""
        try:
            import yaml
            with open(".nsm.yaml", 'r') as f:
                data = yaml.safe_load(f)
            
            if 'secrets' not in data:
                data['secrets'] = {}
            
            data['secrets'][file_name] = secret_id
            
            with open(".nsm.yaml", 'w') as f:
                yaml.dump(data, f, default_flow_style=False)
            
            print(f"Added secret '{file_name}' to .nsm.yaml file")
        except Exception as e:
            print(f"Warning: Failed to update .nsm.yaml file: {e}")
    
    @require_provider
    def clean(self) -> None:
        """
        Delete all secret files listed in .nsm.yaml.
        """
        if not isinstance(self.current_client, PassboltClient):
            print("Error: Clean operation is currently only supported for Passbolt")
            sys.exit(1)
        
        secrets = self._get_secrets_from_yaml()
        if not secrets:
            print("No secrets found in .nsm.yaml file")
            return
        
        deleted_count = 0
        for file_path, secret_id in secrets.items():
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
                    print(f"Deleted file: {file_path}")
                    deleted_count += 1
                else:
                    print(f"File not found (already deleted?): {file_path}")
            except Exception as e:
                print(f"Error deleting file '{file_path}': {e}")
        
        print(f"Clean operation completed. Deleted {deleted_count} files.")
    
    @require_provider
    def restore(self) -> None:
        """
        Restore all secret files from Passbolt using the IDs in .nsm.yaml.
        """
        if not isinstance(self.current_client, PassboltClient):
            print("Error: Restore operation is currently only supported for Passbolt")
            sys.exit(1)
        
        secrets = self._get_secrets_from_yaml()
        if not secrets:
            print("No secrets found in .nsm.yaml file")
            return
        
        restored_count = 0
        for file_path, secret_id in secrets.items():
            try:
                # Get the secret value from Passbolt
                try:
                    output = self.current_client._execute_command("get", "resource", "--id", secret_id, "--json")
                    if not output:
                        print(f"Error: Secret with ID '{secret_id}' not found in Passbolt")
                        continue
                    
                    secret_data = json.loads(output)
                    secret_value = secret_data.get("password", "")
                except Exception as e:
                    print(f"Error getting secret '{file_path}': {e}")
                    continue
                if not secret_value:
                    print(f"Warning: Secret '{file_path}' has empty value")
                
                # Create directory if it doesn't exist
                file_dir = os.path.dirname(file_path)
                if file_dir and not os.path.exists(file_dir):
                    os.makedirs(file_dir, exist_ok=True)
                
                # Write the secret to file
                with open(file_path, 'w') as f:
                    f.write(secret_value)
                
                print(f"Restored file: {file_path}")
                restored_count += 1
                
            except Exception as e:
                print(f"Error restoring file '{file_path}': {e}")
        
        print(f"Restore operation completed. Restored {restored_count} files.")
    
    def _get_secrets_from_yaml(self) -> Dict[str, str]:
        """Get secrets dictionary from .nsm.yaml file."""
        try:
            import yaml
            with open(".nsm.yaml", 'r') as f:
                data = yaml.safe_load(f)
                return data.get('secrets', {})
        except FileNotFoundError:
            print("Error: .nsm.yaml file not found")
            return {}
        except Exception as e:
            print(f"Error: Failed to read .nsm.yaml file: {e}")
            return {}


class ProjectCommands(BaseManager):
    """Project management commands."""
    
    @require_provider
    def create(self, name: str) -> None:
        """
        Create a new project (folder) in the current provider.
        
        Args:
            name: The name of the project to create
        """
        if isinstance(self.current_client, PassboltClient):
            # For Passbolt, use the organization root folder as parent
            provider_config = self.config.get_current_provider()
            if not provider_config or not provider_config.organization_root_folder:
                print("Error: Passbolt provider requires organization_root_folder configuration")
                sys.exit(1)
            
            folder = self.current_client.get_or_create_folder_by_name(name, provider_config.organization_root_folder)
            print(f"Project '{name}' created: {folder['name']} ({folder['id']})")
            
            # Create .nsm.yaml file in current directory
            self._create_nsm_yaml(name, folder['id'])
        else:
            print("Error: Project creation is currently only supported for Passbolt")
            sys.exit(1)
    
    def _create_nsm_yaml(self, project_name: str, project_id: str) -> None:
        """Create a .nsm.yaml file for the project."""
        yaml_content = f"""provider: {self.config.current_provider}
project_id: {project_id}
secrets:
"""
        
        try:
            with open(".nsm.yaml", "w") as f:
                f.write(yaml_content)
            print(f"Created .nsm.yaml file for project '{project_name}'")
        except Exception as e:
            print(f"Warning: Failed to create .nsm.yaml file: {e}")
    
    def secret(self) -> ProjectSecretCommands:
        return ProjectSecretCommands(config=self.config, conf_file=self.conf_file)


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
    
    def passbolt(self) -> PassboltCommands:
        return PassboltCommands(config=self.config, conf_file=self.conf_file)
    
    def project(self) -> ProjectCommands:
        return ProjectCommands(config=self.config, conf_file=self.conf_file)

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
