import tomllib
import typing
from pathlib import Path

from sphinx.util.typing import restify

with open(Path(__file__).parent.parent / "pyproject.toml", "rb") as f:
    _meta = tomllib.load(f)

project = "x690"
copyright = "2020, Michel Albert"
author = "Michel Albert"
release = _meta["project"]["version"]
version = ".".join(release.split(".")[:2])

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosectionlabel",
    "sphinx.ext.intersphinx",
    "sphinx_autodoc_typehints",
    "michel_albert_sphinx",
]

autosectionlabel_prefix_document = True
intersphinx_mapping = {"python": ("https://docs.python.org/3", None)}

exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# sphinx-immaterial links TypeVars in signatures to type parameters. The
# module-level TypeVars in x690.types have no such target.
suppress_warnings = ["ref.param"]

html_title = "x690"
html_baseurl = "https://exhuma.github.io/x690/"
html_theme_options = {
    "repo_url": "https://github.com/exhuma/x690",
    "repo_name": "exhuma/x690",
    "edit_uri": "blob/main/docs",
    "features": [
        "content.code.copy",
        "navigation.top",
        "toc.follow",
    ],
}


def _public_ancestors(cls):  # type: ignore[no-untyped-def]
    """Yield the bases of ``cls``, looking through private classes."""
    for base in getattr(cls, "__orig_bases__", cls.__bases__):
        origin = typing.get_origin(base) or base
        if origin.__name__.startswith("_"):
            yield from _public_ancestors(origin)
        else:
            yield base


def _public_bases(app, name, obj, options, bases):  # type: ignore[no-untyped-def]
    """Replace private base classes with their public ancestors."""
    if any("._" in base for base in bases):
        bases[:] = [restify(base, "smart") for base in _public_ancestors(obj)]


def setup(app):  # type: ignore[no-untyped-def]
    app.connect("autodoc-process-bases", _public_bases)
