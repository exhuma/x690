from sys import version_info

from setuptools import find_packages, setup


def get_version():
    # type: () -> str
    '''
    Retrieves the version information for this package.
    '''
    filename = 'x690/version.py'

    with open(filename) as fptr:
        # pylint: disable=invalid-name, exec-used
        obj = compile(fptr.read(), filename, 'single')
        data = {}  # type: ignore
        exec(obj, data)
    return data['VERSION']


VERSION = get_version()
DEPENDENCIES = [
    'six',
    't61codec >= 1.0.1',
]
if version_info < (3, 5):
    DEPENDENCIES.append('typing')
if version_info < (3, 3):
    DEPENDENCIES.append('ipaddress')
    DEPENDENCIES.append('mock')

TEST_DEPENDENCIES = [
    'pytest',
    'pytest-coverage'
]

setup(
    name="x690",
    version=VERSION,
    description="Pure Python X.690 implementation",
    long_description=open("README.rst").read(),
    author="Michel Albert",
    author_email="michel@albert.lu",
    provides=['x690'],
    license="MIT",
    include_package_data=True,
    package_data={
        'x690': ['py.typed']
    },
    install_requires=DEPENDENCIES,
    extras_require={
        'dev': ['sphinx', 'sphinx-rtd-theme'],
        'test': TEST_DEPENDENCIES
    },
    packages=find_packages(exclude=["tests.*", "tests", "docs"]),
    url="https://github.com/exhuma/x690",
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 2',
        'Typing :: Typed',
    ]
)
