import pytest

import twn_toolkit
from twn_toolkit.app import create_app


@pytest.mark.parametrize("factory", [create_app, twn_toolkit.create_app])
def test_application_factory_requires_an_explicit_instance_in_tests(factory):
    with pytest.raises(AssertionError, match="temporary instance path"):
        factory()


def test_explicit_instance_is_used(tmp_path):
    app = create_app(str(tmp_path))
    assert app.instance_path == str(tmp_path)
