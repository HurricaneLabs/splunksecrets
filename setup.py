from setuptools import setup


VERSION = "0.4.0"


with open("README.rst", "r") as f:
    long_description = f.read()


setup(
    name="splunksecrets",
    version=VERSION,
    author="Steve McMaster",
    author_email="mcmaster@hurricanelabs.com",
    py_modules=["splunksecrets"],
    description="splunksecrets - Encrypt / Decrypt Splunk encrypted passwords",
    long_description=long_description,
    install_requires=[
        "cryptography",
        "pcrypt"
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
