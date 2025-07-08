import json
import subprocess
from typing import List, Dict, Optional, Any
from secrets_manager import SecretsManager, Project, Organization


class PassboltClient(SecretsManager):
    """Passbolt client implementation using the passbolt CLI executable."""

    def __init__(self, organization_root_folder: Optional[str] = None):
        """
        Initialize the Passbolt client.
        
        Args:
            server: The Passbolt server URL (e.g., https://safe.tail961085.ts.net)
            private_key_file: Path to the private key file
            passphrase: The passphrase for the private key
            organization_root_folder: Optional root folder ID to limit project listing
        """
        self.organization_root_folder = organization_root_folder


    def _execute_command(self, *args: str) -> str:
        """Execute a passbolt command and return the output."""
        try:
            cmd = ["passbolt"] + list(args)
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            raise Exception(f"Passbolt command failed: {e}")

    def _execute_json_command(self, *args: str) -> List[Dict[str, Any]]:
        """Execute a passbolt command with --json flag and return parsed JSON."""
        try:
            output = self._execute_command(*args, "--json")
            if not output:
                return []
            return json.loads(output)
        except json.JSONDecodeError as e:
            raise Exception(f"Failed to parse JSON response: {e}")

    def list_organizations(self) -> List[Organization]:
        """List all organizations (folders in Passbolt terminology)."""
        try:
            folders = self._execute_json_command("list", "folder")
            return [
                Organization(id=folder["id"], name=folder["name"]) for folder in folders
            ]
        except Exception as e:
            raise Exception(f"Failed to list organizations: {e}")

    def list_projects(self) -> List[Project]:
        """List all projects (folders in Passbolt terminology)."""
        try:
            if self.organization_root_folder:
                # If organization root folder is specified, only list folders within it
                folders = self._execute_json_command("list", "folder", "-f", self.organization_root_folder)
            else:
                # List all folders
                folders = self._execute_json_command("list", "folder")
            
            return [
                Project(
                    name=folder["name"],
                    id=folder["id"],
                    organization_id=folder.get("folder_parent_id"),
                )
                for folder in folders
            ]
        except Exception as e:
            raise Exception(f"Failed to list projects: {e}")

    def list_secrets(self, project_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List all secrets with optional project filtering.

        Args:
            project_id: Optional folder ID to filter secrets by
        """
        try:
            cmd = ["list", "resource"]
            if project_id:
                cmd.extend(["--filter", f'(FolderId == "{project_id}")'])

            resources = self._execute_json_command(*cmd)
            return [
                {
                    "id": resource["id"],
                    "name": resource["name"],
                    "folder_id": resource.get("folder_parent_id"),
                    "created": resource.get("created"),
                    "modified": resource.get("modified"),
                }
                for resource in resources
            ]
        except Exception as e:
            raise Exception(f"Failed to list secrets: {e}")

    def get_secret(self, name: str, project_id: Optional[str] = None) -> Optional[str]:
        """
        Retrieve a secret by its name.

        Args:
            name: The name of the secret to retrieve
            project_id: Optional folder ID to get the secret from
        """
        try:
            # First, find the resource by name
            cmd = ["list", "resource", "--filter", f'(Name == "{name}")']
            if project_id:
                cmd = [
                    "list",
                    "resource",
                    "--filter",
                    f'(Name == "{name}" && FolderId == "{project_id}")',
                ]

            resources = self._execute_json_command(*cmd)
            if not resources:
                return None

            resource_id = resources[0]["id"]

            # Get the secret value
            secret_data = self._execute_json_command("get", "resource", resource_id)
            if not secret_data:
                return None

            # Extract the password from the secret data
            return secret_data[0].get("password", "")
        except Exception as e:
            raise Exception(f"Failed to get secret '{name}': {e}")

    def store_secret(
        self, name: str, value: str, metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Store a secret with optional metadata.

        Args:
            name: The name of the secret to store
            value: The secret value to store
            metadata: Optional metadata (folder_id, description, etc.)
        """
        try:
            cmd = ["create", "resource", "--name", name, "--password", value]

            # Add optional metadata
            if metadata:
                if "folder_id" in metadata:
                    cmd.extend(["--folderId", metadata["folder_id"]])
                if "description" in metadata:
                    cmd.extend(["--description", metadata["description"]])
                if "uri" in metadata:
                    cmd.extend(["--uri", metadata["uri"]])
                if "username" in metadata:
                    cmd.extend(["--username", metadata["username"]])

            self._execute_command(*cmd)
        except Exception as e:
            raise Exception(f"Failed to store secret '{name}': {e}")

    def delete_secret(self, name: str) -> bool:
        """
        Delete a secret by its name.

        Args:
            name: The name of the secret to delete

        Returns:
            True if the secret was deleted, False if it didn't exist
        """
        try:
            # First, find the resource by name
            resources = self._execute_json_command(
                "list", "resource", "--filter", f'(Name == "{name}")'
            )
            if not resources:
                return False

            resource_id = resources[0]["id"]

            # Delete the resource
            self._execute_command("delete", "resource", resource_id)
            return True
        except Exception as e:
            raise Exception(f"Failed to delete secret '{name}': {e}")

    def create_folder(self, name: str, parent_folder_id: Optional[str] = None) -> str:
        """
        Create a new folder (project) in Passbolt.

        Args:
            name: The name of the folder to create
            parent_folder_id: Optional parent folder ID

        Returns:
            The ID of the created folder
        """
        try:
            cmd = ["create", "folder", "--name", name]
            if parent_folder_id:
                cmd.extend(["--folderId", parent_folder_id])

            result = self._execute_json_command(*cmd)
            if result:
                return result[0]["id"]
            raise Exception("Failed to create folder - no ID returned")
        except Exception as e:
            raise Exception(f"Failed to create folder '{name}': {e}")

    def get_or_create_folder(
        self, name: str, parent_folder_id: Optional[str] = None
    ) -> str:
        """
        Get an existing folder or create it if it doesn't exist.

        Args:
            name: The name of the folder
            parent_folder_id: Optional parent folder ID

        Returns:
            The ID of the folder
        """
        try:
            # Try to find existing folder
            filter_expr = f'(Name == "{name}")'
            if parent_folder_id:
                filter_expr = (
                    f'(Name == "{name}" && FolderParentId == "{parent_folder_id}")'
                )

            folders = self._execute_json_command(
                "list", "folder", "--filter", filter_expr
            )
            if folders:
                return folders[0]["id"]

            # Create new folder if not found
            return self.create_folder(name, parent_folder_id)
        except Exception as e:
            raise Exception(f"Failed to get or create folder '{name}': {e}")

    def list_folders(self, name_filter: Optional[str] = None, parent_folder_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List folders with optional filtering.
        
        Args:
            name_filter: Optional name filter (e.g., "nillebco")
            parent_folder_id: Optional parent folder ID to filter by
            
        Returns:
            List of folder dictionaries
        """
        try:
            cmd = ["list", "folder"]
            
            if name_filter:
                cmd.extend(["--filter", f'(Name == "{name_filter}")'])
            elif parent_folder_id:
                cmd.extend(["-f", parent_folder_id])
            
            return self._execute_json_command(*cmd)
        except Exception as e:
            raise Exception(f"Failed to list folders: {e}")
    
    def get_or_create_folder_by_name(self, name: str, parent_folder_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get an existing folder or create it if it doesn't exist.
        
        Args:
            name: The name of the folder
            parent_folder_id: Optional parent folder ID
            
        Returns:
            Folder dictionary with ID and other details
        """
        try:
            # Try to find existing folder
            filter_expr = f'(Name == "{name}")'
            if parent_folder_id:
                filter_expr = f'(Name == "{name}" && FolderParentId == "{parent_folder_id}")'
            
            folders = self._execute_json_command("list", "folder", "--filter", filter_expr)
            if folders:
                return folders[0]
            
            # Create new folder if not found
            cmd = ["create", "folder", "--name", name]
            if parent_folder_id:
                cmd.extend(["-f", parent_folder_id])
            
            result = self._execute_json_command(*cmd)
            if result:
                return result[0]
            raise Exception("Failed to create folder - no result returned")
        except Exception as e:
            raise Exception(f"Failed to get or create folder '{name}': {e}")
