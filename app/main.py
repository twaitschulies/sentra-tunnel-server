"""
Sentra Tunnel Server - Main Application

FastAPI application for managing remote access to Raspberry Pi door control systems.
"""

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware

from .routes import auth, portal, devices, commands
from .tunnel.broker import TunnelBroker
from .models.database import init_database

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Paths
BASE_DIR = Path(__file__).parent.parent
TEMPLATES_DIR = BASE_DIR / 'app' / 'templates'
STATIC_DIR = BASE_DIR / 'app' / 'static'
DATA_DIR = BASE_DIR / 'data'

# Ensure directories exist
STATIC_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Global tunnel broker instance
tunnel_broker: TunnelBroker = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global tunnel_broker

    # Startup
    logger.info("Starting Sentra Tunnel Server...")

    # Initialize database
    await init_database()

    # Initialize tunnel broker
    tunnel_broker = TunnelBroker()
    app.state.tunnel_broker = tunnel_broker

    logger.info("Server started successfully")

    yield

    # Shutdown
    logger.info("Shutting down...")
    if tunnel_broker:
        await tunnel_broker.shutdown()


# Create FastAPI app
app = FastAPI(
    title="Sentra Tunnel Server",
    description="Central management server for remote door control access",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware (configure as needed for production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for production!
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Templates
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Include routers
app.include_router(auth.router, prefix="/auth", tags=["Authentication"])
app.include_router(portal.router, tags=["Portal"])
app.include_router(devices.router, prefix="/api/devices", tags=["Devices"])
app.include_router(commands.router, prefix="/api/commands", tags=["Commands"])


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": "1.0.0",
        "tunnel_broker": tunnel_broker.get_stats() if tunnel_broker else None
    }


@app.websocket("/ws")
async def websocket_endpoint(websocket):
    """WebSocket endpoint for device tunnel connections."""
    if tunnel_broker:
        await tunnel_broker.handle_connection(websocket)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
