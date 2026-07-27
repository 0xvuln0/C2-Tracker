"""Configuration management for API keys and settings.

Loads credentials from .env files using python-dotenv and validates
that required keys are present before making API calls.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv


@dataclass
class Config:
    """Application configuration holding API credentials.

    Attributes:
        shodan_api_key: Shodan API key.
        censys_api_id: Censys API ID.
        censys_api_secret: Censys API secret.
    """

    shodan_api_key: str = ""
    censys_api_id: str = ""
    censys_api_secret: str = ""

    @classmethod
    def from_env(cls, env_file: str | None = None) -> Config:
        """Load configuration from environment variables / .env file.

        Args:
            env_file: Path to .env file. Defaults to ".env" in cwd.

        Returns:
            Config instance populated from environment.
        """
        load_dotenv(env_file)
        return cls(
            shodan_api_key=os.getenv("SHODAN_API_KEY", ""),
            censys_api_id=os.getenv("CENSYS_API_ID", ""),
            censys_api_secret=os.getenv("CENSYS_API_SECRET", ""),
        )

    def validate(
        self,
        require_shodan: bool = True,
        require_censys: bool = True,
    ) -> list[str]:
        """Check that required API keys are present.

        Args:
            require_shodan: Whether Shodan key is required.
            require_censys: Whether Censys credentials are required.

        Returns:
            List of error messages for missing keys (empty if valid).
        """
        errors: list[str] = []
        if require_shodan and not self.shodan_api_key:
            errors.append("SHODAN_API_KEY is not set")
        if require_censys and not self.censys_api_id:
            errors.append("CENSYS_API_ID is not set")
        if require_censys and not self.censys_api_secret:
            errors.append("CENSYS_API_SECRET is not set")
        return errors
