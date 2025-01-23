from dataclasses import dataclass, field
import json
import os
from typing import Optional, Literal, Dict

@dataclass
class ProviderConfig:
    type: Literal["bitwarden", "google"]
    org: Optional[str] = None  # For Bitwarden
    project_id: Optional[str] = None  # For Google Secrets Manager

@dataclass
class Configuration:
    providers: Dict[str, ProviderConfig] = field(default_factory=dict)
    current_provider: Optional[str] = None

    @classmethod
    def load(cls, file_path: str) -> "Configuration":
        if not os.path.exists(file_path):
            return cls()
        
        with open(file_path, "r") as f:
            data = json.load(f)
            # Convert provider configs to ProviderConfig objects
            if "providers" in data:
                data["providers"] = {
                    name: ProviderConfig(**config) 
                    for name, config in data["providers"].items()
                }
            return cls(**data)

    def save(self, file_path: str) -> None:
        # Convert to dict for JSON serialization
        data = {
            "providers": {
                name: vars(config)
                for name, config in self.providers.items()
            },
            "current_provider": self.current_provider
        }
        with open(file_path, "w") as f:
            json.dump(data, f)

    def add_provider(self, name: str, provider_type: Literal["bitwarden", "google"], 
                    org: Optional[str] = None, project_id: Optional[str] = None) -> None:
        """Add or update a provider configuration."""
        self.providers[name] = ProviderConfig(
            type=provider_type,
            org=org,
            project_id=project_id
        )
        
    def get_current_provider(self) -> Optional[ProviderConfig]:
        """Get the current provider configuration."""
        if not self.current_provider or self.current_provider not in self.providers:
            return None
        return self.providers[self.current_provider]