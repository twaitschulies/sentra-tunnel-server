"""
Device Models

Pydantic models for device data validation.
"""

from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


class DeviceBase(BaseModel):
    """Base device model."""
    name: Optional[str] = None
    shop_id: Optional[str] = None


class DeviceCreate(DeviceBase):
    """Model for creating a device."""
    device_id: str = Field(..., description="Device hostname")
    mac_address: Optional[str] = None


class DeviceUpdate(DeviceBase):
    """Model for updating a device."""
    pass


class Device(DeviceBase):
    """Full device model."""
    device_id: str
    mac_address: Optional[str] = None
    api_key: str
    fingerprint: Optional[str] = None
    registered_at: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    status: str = 'offline'

    class Config:
        from_attributes = True


class DeviceStatus(BaseModel):
    """Device status response."""
    device_id: str
    name: Optional[str] = None
    shop_id: Optional[str] = None
    online: bool
    status: str
    last_seen: Optional[str] = None
    last_heartbeat: Optional[str] = None
    door_status: Optional[dict] = None


class DeviceRegistration(BaseModel):
    """Device registration request."""
    registration_token: str
    device_id: str
    mac_address: Optional[str] = None
    fingerprint: Optional[str] = None
    timestamp: Optional[str] = None


class DeviceRegistrationResponse(BaseModel):
    """Device registration response."""
    success: bool
    device_id: Optional[str] = None
    api_key: Optional[str] = None
    tunnel_url: Optional[str] = None
    error: Optional[str] = None


class CreateDeviceRequest(BaseModel):
    """Request to create a device (generates registration token)."""
    shop_id: str
    device_name: str


class CreateDeviceResponse(BaseModel):
    """Response with registration token."""
    device_id: str
    registration_token: str
    expires_at: str
