import json
import subprocess
from typing import List, Dict, Optional, Any
from datetime import datetime
import socket
import os
from secrets_manager import SecretsManager


class BitwardenClient(SecretsManager):
    def __init__(self, org: str):
        self.org = org

    def _get_keychain_secret_name(self) -> str:
        """Generate the keychain secret name for the access token."""
        host_name = socket.gethostname()
        host_name = host_name.replace(".local", "")
        suffix = datetime.now().year
        return f"bws-{self.org}-{host_name}-{suffix}"

    def set_access_token(self, token: str) -> None:
        """
        Store the Bitwarden access token in the system keychain.
        
        Args:
            token: The access token to store
        """
        secret_name = self._get_keychain_secret_name()
        cmd = f"security add-generic-password -a none -s {secret_name} -w {token}"
        try:
            subprocess.run(cmd, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            raise Exception(f"Failed to store access token: {e}")

    def get_access_token(self) -> str:
        """Retrieve the Bitwarden access token from the system keychain."""
        secret_name = self._get_keychain_secret_name()
        secret_value = os.popen(
            f"security find-generic-password -a none -s {secret_name} -w"
        ).read()
        return secret_value.rstrip()

    def execute_command(self, *args: str) -> None:
        args = [f'"{arg}"' for arg in args]
        cmd = f"bws --access-token {self.get_access_token()} {' '.join(args)}"
        try:
            subprocess.run(cmd, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            raise e

    def get_organizations(self) -> List[str]:
        cmd = f"bws --access-token {self.get_access_token()} project list"
        result = subprocess.run(
            cmd, shell=True, check=True, capture_output=True, text=True
        )
        projects = json.loads(result.stdout)
        return list(set([project["organizationId"] for project in projects]))

    def get_projects(self) -> List[Dict]:
        cmd = f"bws --access-token {self.get_access_token()} project list"
        result = subprocess.run(
            cmd, shell=True, check=True, capture_output=True, text=True
        )
        return json.loads(result.stdout)

    def _resolve_project_id(self, project_name: str) -> Optional[str]:
        """
        Resolve a project name to its ID using the local project list.
        
        Args:
            project_name: The name of the project to resolve
            
        Returns:
            The project ID if found, None otherwise
        """
        projects = self.get_projects()
        for project in projects:
            if project["name"] == project_name:
                return project["id"]
        return None

    def list_secrets(self, project_id: Optional[str] = None) -> list[Dict[str, Any]]:
        """
        List all secrets with optional project filtering.
        
        Args:
            project_id: Optional project name or ID to filter secrets by
        """
        cmd = f"bws --access-token {self.get_access_token()} secret list"
        
        if project_id:
            # Try to resolve the project name to an ID if it's not already an ID format
            if not project_id.count("-") == 4:  # Simple UUID check
                resolved_id = self._resolve_project_id(project_id)
                if resolved_id:
                    project_id = resolved_id
                else:
                    raise ValueError(f"Project '{project_id}' not found")
            
            cmd += f" {project_id}"
            
        result = subprocess.run(
            cmd, shell=True, check=True, capture_output=True, text=True
        )
        return json.loads(result.stdout)

    def get_secret(self, name: str) -> Optional[str]:
        secrets = self.list_secrets()
        for secret in secrets:
            if secret["key"] == name:
                return secret["value"]
        return None

    def store_secret(self, name: str, value: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        # Create a temporary file with the secret value
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp:
            temp.write(value)
            temp_path = temp.name

        try:
            cmd = f"bws --access-token {self.get_access_token()} secret create {name} {temp_path}"
            if metadata:
                for key, value in metadata.items():
                    cmd += f" --{key} {value}"
            subprocess.run(cmd, shell=True, check=True)
        finally:
            os.unlink(temp_path)

    def delete_secret(self, name: str) -> bool:
        # First check if the secret exists
        if not self.get_secret(name):
            return False
        
        cmd = f"bws --access-token {self.get_access_token()} secret delete {name}"
        try:
            subprocess.run(cmd, shell=True, check=True)
            return True
        except subprocess.CalledProcessError:
            raise Exception(f"Failed to delete secret {name}")

    # Legacy method names for backward compatibility
    get_secrets = list_secrets
    get_secret_value = get_secret 