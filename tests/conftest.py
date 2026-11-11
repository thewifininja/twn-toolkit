"""Suite-wide isolation from an installed toolkit's runtime data.

A checkout is also a normal installation layout: ``./twn`` keeps live state in
``<checkout>/instance``, which is Flask's default instance path. Building the
application without an explicit path would therefore run migrations against,
and open every store in, that live directory. Tests must always name their own
temporary instance.
"""

from __future__ import annotations

import functools

import twn_toolkit
import twn_toolkit.app as toolkit_app

_create_app = toolkit_app.create_app


@functools.wraps(_create_app)
def _isolated_create_app(instance_path=None, *args, **kwargs):
    if instance_path is None:
        raise AssertionError(
            "Tests must pass create_app() a temporary instance path; the default "
            "is the checkout's instance/ directory, which may hold live data."
        )
    return _create_app(instance_path, *args, **kwargs)


toolkit_app.create_app = _isolated_create_app
twn_toolkit.create_app = _isolated_create_app
