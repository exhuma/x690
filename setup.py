"""
Standard Python setup script
"""
from setuptools import find_packages, setup  # type: ignore

with open("README.rst") as fp:
    LONG_DESC = fp.read()

setup(
    name="x690",
    version="0.5.0a6",
    description="Pure Python X.690 implementation",
    long_description=LONG_DESC,
    author="Michel Albert",
    author_email="michel@albert.lu",
    license="MIT",
    include_package_data=True,
    package_data={"x690": ["py.typed"]},
    install_requires=[
        'dataclasses; python_version < "3.7"',
        'importlib_metadata; python_version < "3.8"',
        "t61codec >= 1.0.1, <2.0",
    ],
    extras_require={
        "dev": [
            "Pygments",
            "black",
            "isort",
            "mypy",
            "pylint",
            "pytest",
            "pytest-coverage",
            "sphinx",
            "sphinx-rtd-theme",
            "types-dataclasses",
            "vulture",
        ],
        "test": ["pytest"],
        "webui": ["flask"],
    },
    packages=find_packages(exclude=["tests.*", "tests"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Typing :: Typed",
    ],
    url="https://exhuma.github.io/x690/",
    project_urls={
        "Bug Tracker": "https://exhuma.github.io/x690/issues",
    },
    python_requires=">=3.6",
)
