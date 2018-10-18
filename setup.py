import subprocess
from setuptools import setup, find_packages


VERSION = "0.1.0"


setup(
    name="splunksecrets",
    version=VERSION,
    author="Steve McMaster",
    author_email="mcmaster@hurricanelabs.com",
    py_modules=["splunksecrets"],
    # url="http://hurricanelabs.github.io/flunk/",
    description="splunksecrets - Encrypt / Decrypt Splunk encrypted passwords",
    install_requires=[
        "cryptography",
    ],
    entry_points={
        "console_scripts": [
            "splunksecrets = splunksecrets:main",
        ]
    },
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Development Status :: 5 - Production/Stable",
    ],
    bugtrack_url="https://github.com/HurricaneLabs/splunksecrets/issues",
)
