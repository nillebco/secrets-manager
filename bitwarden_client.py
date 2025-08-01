import json
import subprocess
from typing import List, Dict, Optional, Any
from datetime import datetime
import socket
import os
from secrets_manager import SecretsManager, Project, Organization


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
        try:
            result = subprocess.run(
                f"security find-generic-password -a none -s {secret_name} -w",
                shell=True,
                check=True,
                capture_output=True,
                text=True,
            )
            token = result.stdout.strip()
            if not token:
                raise Exception(
                    f"Access token not found in keychain for service '{secret_name}'"
                )
            return token
        except subprocess.CalledProcessError as e:
            raise Exception(f"Failed to retrieve access token from keychain: {e}")

    def execute_command(self, *args: str) -> None:
        args = [f'"{arg}"' for arg in args]
        try:
            access_token = self.get_access_token()
            cmd = f"bws --access-token {access_token} {' '.join(args)}"
            subprocess.run(cmd, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            raise Exception(f"bws command failed: {e}")
        except Exception as e:
            raise Exception(f"Failed to execute bws command: {e}")

    def list_organizations(self) -> List[Organization]:
        try:
            access_token = self.get_access_token()
            cmd = f"bws --access-token {access_token} organization list"
            result = subprocess.run(
                cmd, shell=True, check=True, capture_output=True, text=True
            )
            organizations = json.loads(result.stdout)
            return [
                Organization(id=org["id"], name=org["name"]) for org in organizations
            ]
        except subprocess.CalledProcessError as e:
            raise Exception(f"Failed to list organizations: {e}")
        except json.JSONDecodeError as e:
            raise Exception(f"Failed to parse organizations response: {e}")
        except Exception as e:
            raise Exception(f"Failed to list organizations: {e}")

    def list_projects(self) -> List[Project]:
        try:
            access_token = self.get_access_token()
            cmd = f"bws --access-token {access_token} project list"
            result = subprocess.run(
                cmd, shell=True, check=True, capture_output=True, text=True
            )
            projects_dicts = json.loads(result.stdout)
            return [
                Project(
                    name=project.get("name"),
                    id=project.get("id"),
                    organization_id=project.get("organizationId"),
                )
                for project in projects_dicts
            ]
        except subprocess.CalledProcessError as e:
            raise Exception(f"Failed to list projects: {e}")
        except json.JSONDecodeError as e:
            raise Exception(f"Failed to parse projects response: {e}")
        except Exception as e:
            raise Exception(f"Failed to list projects: {e}")

    def _resolve_project_id(self, project_name: str) -> Optional[str]:
        """
        Resolve a project name to its ID using the local project list.

        Args:
            project_name: The name of the project to resolve

        Returns:
            The project ID if found, None otherwise
        """
        projects = self.list_projects()
        for project in projects:
            if project.name == project_name:
                return project.id
        return None

    def list_secrets(self, project_id: Optional[str] = None) -> list[Dict[str, Any]]:
        """
        List all secrets with optional project filtering.

        Args:
            project_id: Optional project name or ID to filter secrets by
        """
        try:
            access_token = self.get_access_token()
            cmd = f"bws --access-token {access_token} secret list"

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
        except subprocess.CalledProcessError as e:
            raise Exception(f"Failed to list secrets: {e}")
        except json.JSONDecodeError as e:
            raise Exception(f"Failed to parse secrets response: {e}")
        except Exception as e:
            raise Exception(f"Failed to list secrets: {e}")

    def get_secret(self, name: str, project_id: Optional[str] = None) -> Optional[str]:
        """
        Retrieve a secret by its name.

        Args:
            name: The name/key of the secret to retrieve
            project_id: Optional project name or ID to get the secret from
        """
        # If project_id is provided, resolve it if it's a name
        if project_id and not project_id.count("-") == 4:  # Simple UUID check
            resolved_id = self._resolve_project_id(project_id)
            if resolved_id:
                project_id = resolved_id
            else:
                raise ValueError(f"Project '{project_id}' not found")

        # Get secrets from the specific project or all secrets if no project specified
        secrets = self.list_secrets(project_id)
        for secret in secrets:
            if secret["key"] == name:
                return secret["value"]
        return None

    def store_secret(
        self, name: str, value: str, metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        # Create a temporary file with the secret value
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as temp:
            temp.write(value)
            temp_path = temp.name

        try:
            access_token = self.get_access_token()
            cmd = f"bws --access-token {access_token} secret create {name} {temp_path}"
            if metadata:
                for key, value in metadata.items():
                    cmd += f" --{key} {value}"
            subprocess.run(cmd, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            raise Exception(f"Failed to store secret: {e}")
        except Exception as e:
            raise Exception(f"Failed to store secret: {e}")
        finally:
            os.unlink(temp_path)

    def delete_secret(self, name: str) -> bool:
        # First check if the secret exists
        if not self.get_secret(name):
            return False

        try:
            access_token = self.get_access_token()
            cmd = f"bws --access-token {access_token} secret delete {name}"
            subprocess.run(cmd, shell=True, check=True)
            return True
        except subprocess.CalledProcessError as e:
            raise Exception(f"Failed to delete secret {name}: {e}")
        except Exception as e:
            raise Exception(f"Failed to delete secret {name}: {e}")

    # Legacy method names for backward compatibility
    get_secrets = list_secrets
    get_secret_value = get_secret
