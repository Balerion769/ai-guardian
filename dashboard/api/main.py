"""ASGI entry point for Render and other hosted API deployments."""

from dashboard.app import create_app

app = create_app()
