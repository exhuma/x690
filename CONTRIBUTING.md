# Contributing

## Scope

The library implements a fixed standard (ITU-T X.690, BER encoding) and is
feature-complete. The project is in **maintenance mode**. Accepted:

- bug fixes,
- support for new Python versions,
- security fixes,
- documentation and tooling improvements.

Feature requests are declined unless a change in Python itself requires one.

## Getting started

1. Fork the repository and clone your fork.
2. Install [uv](https://docs.astral.sh/uv/).
3. Install the project and its development dependencies:

   ```console
   uv sync
   ```

4. Install the pre-commit hooks:

   ```console
   uv run pre-commit install
   ```

## Running tests

```console
uv run pytest
```

Doctests run on the `x690` package as part of the test run. Coverage must
stay at or above 99% (`--cov-fail-under=99`, configured in `pyproject.toml`).

## Code style

This project uses [ruff](https://docs.astral.sh/ruff/) for linting and
formatting, and `mypy` in strict mode. The pre-commit hooks enforce these
checks automatically. You can also run them manually:

```console
uv run pre-commit run --all-files
```

## Submitting changes

Please open a pull request with a clear description of what was changed and
why. If you are fixing a bug, include a test that reproduces the original
problem. Commits follow [Conventional Commits](https://www.conventionalcommits.org/).

## Python support policy

CI tests every CPython version that is currently supported. The list is
computed automatically from [endoflife.date](https://endoflife.date/python),
plus the upcoming pre-release (informational only). A monthly scheduled run
detects breakage caused by new Python releases.

`requires-python` is the oldest supported version at release time. It is only
raised when cutting a release; a CI warning signals when it is due. Update the
`Programming Language :: Python :: 3.x` classifiers at the same time.

## Dependency updates

The only runtime dependency is `t61codec` (`>=3.0,<4`). Development tools are
pinned in `uv.lock` and `.pre-commit-config.yaml`, and GitHub Actions are
pinned by tag, so nothing changes unless a maintainer updates it on purpose.
There are no automated version-update PRs: the monthly scheduled CI run is the
signal. When it fails because of an outdated tool or action, update it then
(`uv lock --upgrade`, `uv run pre-commit autoupdate`, or bump the action).

## Documentation

The Sphinx docs are built with `-W` (warnings are errors) on every push and
pull request (CI), and published to GitHub Pages
(https://exhuma.github.io/x690/) by `.github/workflows/docs.yml` on every push
to `main`. To build locally:

```console
uv run sphinx-apidoc -o docs/api x690
uv run sphinx-build -W -b html docs docs/_build/html
```

`docs/api` and `docs/_build` are generated and git-ignored.

## Release procedure

1. Bump `version` in `pyproject.toml`, update `docs/changelog.rst`, and update
   the classifiers and `requires-python` if needed.
2. Merge to `main`.
3. Tag the release as `vX.Y.Z` and push the tag.
4. CI builds and inspects the packages (`hynek/build-and-inspect-python-package`,
   which also runs on every PR) and publishes that exact build to PyPI through
   Trusted Publishing (the job fails if the tag does not match the package
   version).

### One-time setup

Needed only once:

- On PyPI, add a trusted publisher to the project: owner `exhuma`, repository
  `x690`, workflow `pythonpackage.yml`, environment `pypi`.
- In the GitHub repository settings, create the `pypi` environment.
- In the GitHub repository settings, set Pages to deploy from "GitHub
  Actions".
