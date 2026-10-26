from importlib.metadata import version as _version

project = "x690"
copyright = "2020, Michel Albert"
author = "Michel Albert"
release = _version("x690")

extensions = [
    "sphinx.ext.autodoc",
    "michel_albert_sphinx",
]

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
