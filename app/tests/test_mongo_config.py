from types import SimpleNamespace

import pytest

from app.db.mongo import resolve_mongo_uri


def test_resolve_mongo_uri_prefers_direct_uri() -> None:
    settings = SimpleNamespace(
        mongo_uri="mongodb+srv://u:p@cluster.mongodb.net/?retryWrites=true&w=majority",
        mongo_user="ignored",
        mongo_password="ignored",
        mongo_host="ignored",
        mongo_db="cybersentinel",
    )
    assert resolve_mongo_uri(settings) == settings.mongo_uri


def test_resolve_mongo_uri_builds_from_split_vars() -> None:
    settings = SimpleNamespace(
        mongo_uri="",
        mongo_user="alice",
        mongo_password="p@ss",
        mongo_host="cluster.mongodb.net",
        mongo_db="cybersentinel",
    )
    resolved = resolve_mongo_uri(settings)
    assert resolved.startswith("mongodb+srv://alice:p%40ss@cluster.mongodb.net/cybersentinel")


def test_resolve_mongo_uri_raises_when_incomplete() -> None:
    settings = SimpleNamespace(
        mongo_uri="",
        mongo_user="",
        mongo_password="",
        mongo_host="",
        mongo_db="cybersentinel",
    )
    with pytest.raises(RuntimeError):
        resolve_mongo_uri(settings)
