from abc import ABC, abstractmethod
from typing import Optional, Any, Dict
from dataclasses import dataclass


@dataclass
class Organization:
    """Represents an organization in a secrets provider."""

    id: str
    name: str


@dataclass
class Project:
    """Represents a project in a secrets manager."""

    name: str
    id: str
    organization_id: Optional[str] = None


class SecretsManager(ABC):
    """Abstract base class defining the interface for a secrets manager."""

    @abstractmethod
    def get_secret(self, name: str, project_id: Optional[str] = None) -> Optional[str]:
        """
        Retrieve a secret by its name.

        Args:
            name: The name/key of the secret to retrieve
            project_id: Optional project ID to get the secret from

        Returns:
            The secret value if found, None otherwise
        """
        pass

    @abstractmethod
    def store_secret(
        self, name: str, value: str, metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Store a secret with an optional metadata dictionary.

        Args:
            name: The name/key to store the secret under
            value: The secret value to store
            metadata: Optional dictionary of metadata to store with the secret

        Raises:
            Exception: If the secret cannot be stored
        """
        pass

    @abstractmethod
    def list_secrets(self, project_id: Optional[str] = None) -> list[Dict[str, Any]]:
        """
        List all available secrets with their metadata.

        Args:
            project_id: Optional project ID to filter secrets by

        Returns:
            List of dictionaries containing secret information (excluding values)
        """
        pass

    @abstractmethod
    def delete_secret(self, name: str) -> bool:
        """
        Delete a secret by its name.

        Args:
            name: The name/key of the secret to delete

        Returns:
            True if the secret was deleted, False if it didn't exist

        Raises:
            Exception: If the secret exists but cannot be deleted
        """
        pass

    @abstractmethod
    def list_projects(self) -> list[Project]:
        """
        List all available projects in the organization.

        Returns:
            A list of Project objects containing project information
        """
        pass

    @abstractmethod
    def list_organizations(self) -> list[Organization]:
        """
        List all available organizations in the secrets manager.

        Returns:
            A list of Organization objects containing organization information
        """
        pass
