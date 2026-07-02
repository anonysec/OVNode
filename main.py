import uvicorn
from core.config import settings
from core.logger import logger


def main():
    logger.info("Starting OV-Node...")
    # reload=True is a development-only feature (extra watcher process + constant
    # filesystem polling). Disabled to keep the node lightweight.
    uvicorn.run(
        "core.app:api",
        host="0.0.0.0",
        port=settings.service_port,
        reload=False,
        workers=1,
    )


if __name__ == "__main__":
    main()
