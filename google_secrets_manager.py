import json
import subprocess
from typing import Optional, Any, Dict
from secrets_manager import SecretsManager


class GoogleSecretsManager(SecretsManager):
    """Implementation of SecretsManager using Google Cloud Secret Manager via gcloud CLI."""
    
    def __init__(self, project_id: str):
        """
        Initialize the Google Secrets Manager client.
        
        Args:
            project_id: The Google Cloud project ID
        """
        self.project_id = project_id
        self._verify_gcloud_installation()
        
    def _verify_gcloud_installation(self) -> None:
        """Verify that gcloud CLI is installed and configured."""
        try:
            subprocess.run(["gcloud", "--version"], check=True, capture_output=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise RuntimeError("gcloud CLI is not installed or not in PATH")
            
    def _format_secret_name(self, name: str) -> str:
        """Format the secret name to match Google Secret Manager requirements."""
        return f"projects/{self.project_id}/secrets/{name}"
        
    def get_secret(self, name: str) -> Optional[str]:
        """Retrieve a secret by its name."""
        try:
            result = subprocess.run(
                ["gcloud", "secrets", "versions", "access", "latest", 
                 "--secret", name,
                 "--project", self.project_id],
                check=True,
                capture_output=True,
                text=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            return None
            
    def store_secret(self, name: str, value: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Store a secret with optional metadata."""
        try:
            # Create or update the secret
            try:
                subprocess.run(
                    ["gcloud", "secrets", "create", name,
                     "--project", self.project_id],
                    check=True,
                    capture_output=True
                )
            except subprocess.CalledProcessError:
                # Secret might already exist, which is fine
                pass
                
            # Add the new version with the value
            subprocess.run(
                ["gcloud", "secrets", "versions", "add", name,
                 "--data-file=-",
                 "--project", self.project_id],
                input=value.encode(),
                check=True
            )
            
            # Update metadata if provided
            if metadata:
                labels = [f"{k}={v}" for k, v in metadata.items() if isinstance(v, str)]
                if labels:
                    subprocess.run(
                        ["gcloud", "secrets", "update", name,
                         f"--update-labels={','.join(labels)}",
                         "--project", self.project_id],
                        check=True
                    )
                    
        except subprocess.CalledProcessError as e:
            raise Exception(f"Failed to store secret: {e}")
            
    def list_secrets(self) -> list[Dict[str, Any]]:
        """List all available secrets with their metadata."""
        try:
            result = subprocess.run(
                ["gcloud", "secrets", "list",
                 "--format=json",
                 "--project", self.project_id],
                check=True,
                capture_output=True,
                text=True
            )
            secrets = json.loads(result.stdout)
            return [
                {
                    "name": secret["name"].split("/")[-1],
                    "metadata": secret.get("labels", {}),
                    "create_time": secret.get("createTime"),
                    "project_id": self.project_id
                }
                for secret in secrets
            ]
        except subprocess.CalledProcessError as e:
            raise Exception(f"Failed to list secrets: {e}")
            
    def delete_secret(self, name: str) -> bool:
        """Delete a secret by its name."""
        try:
            subprocess.run(
                ["gcloud", "secrets", "delete", name,
                 "--project", self.project_id,
                 "--quiet"],  # Skip confirmation prompt
                check=True,
                capture_output=True
            )
            return True
        except subprocess.CalledProcessError:
            return False 