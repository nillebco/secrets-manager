from dataclasses import dataclass
import json
import os
from typing import Optional, Literal


@dataclass
class Configuration:
    provider: Optional[Literal["bitwarden", "google"]] = None
    org: Optional[str] = None
    project_id: Optional[str] = None

    @classmethod
    def load(cls, file_path: str) -> "Configuration":
        if not os.path.exists(file_path):
            return cls()
        
        with open(file_path, "r") as f:
            data = json.load(f)
            return cls(**data)

    def save(self, file_path: str) -> None:
        with open(file_path, "w") as f:
            json.dump(self.__dict__, f)