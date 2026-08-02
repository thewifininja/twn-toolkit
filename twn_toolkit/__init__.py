from .version import APP_VERSION

__version__ = APP_VERSION


def create_app(*args, **kwargs):
    """Load the Flask application only when the web server requests it."""
    from .app import create_app as app_factory

    return app_factory(*args, **kwargs)
