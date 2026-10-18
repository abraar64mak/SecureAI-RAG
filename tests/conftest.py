import pytest

from target.rag import World


@pytest.fixture(scope="session")
def world():
    return World()
