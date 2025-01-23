from abc import ABC, abstractmethod
from typing import Optional, Any, Dict


class SecretsManager(ABC):
    """Abstract base class defining the interface for a secrets manager."""
    
    @abstractmethod
    def get_secret(self, name: str) -> Optional[str]:
        """
        Retrieve a secret by its name.
        
        Args:
            name: The name/key of the secret to retrieve
            
        Returns:
            The secret value if found, None otherwise
        """
        pass
    
    @abstractmethod
    def store_secret(self, name: str, value: str, metadata: Optional[Dict[str, Any]] = None) -> None:
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
    def list_secrets(self) -> list[Dict[str, Any]]:
        """
        List all available secrets with their metadata.
        
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