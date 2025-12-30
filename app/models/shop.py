"""
Shop Models

Pydantic models for shop/tenant data validation.
"""

from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime


class ShopBase(BaseModel):
    """Base shop model."""
    name: str


class ShopCreate(ShopBase):
    """Model for creating a shop."""
    id: Optional[str] = None  # Auto-generated if not provided


class ShopUpdate(BaseModel):
    """Model for updating a shop."""
    name: Optional[str] = None


class Shop(ShopBase):
    """Full shop model."""
    id: str
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ShopWithDevices(Shop):
    """Shop model with device list."""
    devices: List[dict] = []
    online_count: int = 0
    total_count: int = 0


class ShopSummary(BaseModel):
    """Shop summary for dashboard."""
    id: str
    name: str
    device_count: int
    online_count: int
    last_activity: Optional[str] = None
