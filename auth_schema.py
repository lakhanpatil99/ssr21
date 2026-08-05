from pydantic import BaseModel, UUID4, field_validator
from typing import Optional
import re


class EnrollmentRequest(BaseModel):
    """Request model for device enrollment."""
    enrollment_token: str
    device_id: UUID4
    hostname: str
    os_version: str
    agent_version: str
    ip_address: Optional[str] = None
    
    @field_validator('hostname')
    @classmethod
    def validate_hostname(cls, v: str) -> str:
        """Validate hostname format."""
        if not v or len(v) > 255:
            raise ValueError("Hostname must be 1-255 characters")
        # Basic hostname validation
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$', v.split('.')[0]):
            raise ValueError("Invalid hostname format")
        return v
    
    @field_validator('os_version')
    @classmethod
    def validate_os_version(cls, v: str) -> str:
        """Validate OS version string."""
        if not v or len(v) > 128:
            raise ValueError("OS version must be 1-128 characters")
        return v
    
    @field_validator('agent_version')
    @classmethod
    def validate_agent_version(cls, v: str) -> str:
        """Validate agent version format."""
        if not v or len(v) > 32:
            raise ValueError("Agent version must be 1-32 characters")
        # Basic semver-like validation
        if not re.match(r'^\d+\.\d+\.\d+', v):
            raise ValueError("Agent version must start with semver format (e.g., 1.0.0)")
        return v
    
    @field_validator('ip_address')
    @classmethod
    def validate_ip_address(cls, v: Optional[str]) -> Optional[str]:
        """Validate IP address format if provided."""
        if v is None:
            return v
        # Basic IPv4/IPv6 validation
        if not re.match(r'^[\d.:a-fA-F]+$', v):
            raise ValueError("Invalid IP address format")
        return v


class AuthResponse(BaseModel):
    """Response model for authentication with access and refresh tokens."""
    device_token: str
    refresh_token: Optional[str] = None
    expires_in: int
    token_type: str = "Bearer"


class TokenRefreshResponse(BaseModel):
    """Response model for token refresh endpoint."""
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
