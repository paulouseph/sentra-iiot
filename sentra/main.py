"""
main.py
-------
Application entry point.

    uvicorn sentra.main:app --reload

The server also serves the dashboard at / from frontend/, so there is one
process and one origin to think about -- no separate static server, no CORS
surprises during a demo.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import runtime as rt_module
from .api import alerts, detect, system
from .config import get_settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s %(name)s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("sentra")

DESCRIPTION = """
Threat detection for industrial IoT networks, trained on the Edge-IIoTset corpus.

**Reads are open. Anything that changes state needs the `X-API-Key` header.**

* `POST /api/predict` — classify one flow
* `POST /api/simulate` — inject a drill burst drawn from held-out real traffic
* `GET  /api/alerts` — the triage feed
* `GET  /api/model/card` — full evaluation report
* `WS   /ws/live` — push channel for new alerts
"""


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    app.state.runtime = rt_module.build(settings)
    if app.state.runtime.stream:
        app.state.runtime.stream.start()
        log.info("Live stream started (%d ms interval).",
                 app.state.runtime.stream.interval_ms)
    else:
        log.warning("Running without a model. Train first: python -m sentra.ml.train")
    log.info("Dashboard: http://%s:%s/", settings.host, settings.port)
    try:
        yield
    finally:
        if app.state.runtime.stream:
            await app.state.runtime.stream.stop()
        app.state.runtime.shutdown()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="SENTRA-IIoT",
        description=DESCRIPTION,
        version=rt_module.VERSION,
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "X-API-Key"],
    )

    app.include_router(system.router)
    app.include_router(detect.router)
    app.include_router(alerts.router)

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        log.exception("Unhandled error on %s", request.url.path)
        return JSONResponse(
            status_code=500,
            content={
                "detail": "Something failed server-side. Check the server log for the traceback.",
                "path": request.url.path,
            },
        )

    frontend: Path = settings.frontend_dir
    if frontend.exists():
        app.mount("/static", StaticFiles(directory=frontend), name="static")

        @app.get("/", include_in_schema=False)
        def dashboard():
            return FileResponse(frontend / "index.html")

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    s = get_settings()
    uvicorn.run("sentra.main:app", host=s.host, port=s.port, reload=True)
