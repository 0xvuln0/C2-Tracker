from __future__ import annotations

import os
from dataclasses import dataclass, field

from dotenv import load_dotenv


@dataclass
class Config:
    shodan_api_key: str = ""
    censys_api_id: str = ""
    censys_api_secret: str = ""

    @classmethod
    def from_env(cls, env_file: str | None = None) -> Config:
        load_dotenv(env_file)
        return cls(
            shodan_api_key=os.getenv("SHODAN_API_KEY", ""),
            censys_api_id=os.getenv("CENSYS_API_ID", ""),
            censys_api_secret=os.getenv("CENSYS_API_SECRET", ""),
        )

    def validate(self, require_shodan: bool = True, require_censys: bool = True) -> list[str]:
        errors = []
        if require_shodan and not self.shodan_api_key:
            errors.append("SHODAN_API_KEY is not set")
        if require_censys and not self.censys_api_id:
            errors.append("CENSYS_API_ID is not set")
        if require_censys and not self.censys_api_secret:
            errors.append("CENSYS_API_SECRET is not set")
        return errors
