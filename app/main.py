"""
Sentra Tunnel Server - Main Application

FastAPI application for managing remote access to Raspberry Pi door control systems.
"""

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

from .routes import auth, portal, devices, commands
from .tunnel.broker import TunnelBroker
from .models.database import init_database, create_demo_shop, DEMO_SHOP_ID, DEMO_DEVICES

# Configure logging with file handler for troubleshooting
LOG_DIR = Path(__file__).parent.parent / 'data' / 'logs'
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
))

# File handler for detailed logs
file_handler = logging.FileHandler(LOG_DIR / 'server.log')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
))

# Error file handler for errors only
error_handler = logging.FileHandler(LOG_DIR / 'errors.log')
error_handler.setLevel(logging.ERROR)
error_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d\n%(message)s\n'
))

# Configure root logger
logging.basicConfig(
    level=logging.DEBUG,
    handlers=[console_handler, file_handler, error_handler]
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

    # Create demo shop and devices
    await create_demo_shop()

    # Initialize tunnel broker
    tunnel_broker = TunnelBroker()
    app.state.tunnel_broker = tunnel_broker

    # Register demo devices as "connected"
    for device in DEMO_DEVICES:
        tunnel_broker.register_demo_device(
            device_id=device["device_id"],
            shop_id=DEMO_SHOP_ID,
            name=device["name"]
        )

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


# Exception handlers for HTML pages
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions - redirect to login for 401, show error page for others."""
    # Check if this is an API request (expects JSON)
    accept = request.headers.get("accept", "")
    if "application/json" in accept or request.url.path.startswith("/api/"):
        # Return JSON for API requests
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail}
        )

    # For HTML pages, redirect to login on 401
    if exc.status_code == 401:
        return RedirectResponse(url="/login", status_code=302)

    # For other errors, show error page
    return templates.TemplateResponse(
        "pages/error.html",
        {
            "request": request,
            "user": None,
            "error": exc.detail,
            "error_code": exc.status_code
        },
        status_code=exc.status_code
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected exceptions."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)

    # Check if this is an API request
    accept = request.headers.get("accept", "")
    if "application/json" in accept or request.url.path.startswith("/api/"):
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"}
        )

    return templates.TemplateResponse(
        "pages/error.html",
        {
            "request": request,
            "user": None,
            "error": str(exc),
            "error_code": 500
        },
        status_code=500
    )


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
