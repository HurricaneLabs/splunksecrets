import click
import pcrypt
import re
from cryptography.hazmat.primitives import serialization

from .dbconnect import encrypt_dbconnect, decrypt_dbconnect
from .phantom import encrypt_phantom, decrypt_phantom
from .splunk import encrypt, encrypt_new, decrypt


def __ensure_binary(ctx, param, value):
    if value is None and not param.required:
        return None
    if isinstance(value, str):
        value = value.encode()
    return value


def __ensure_int(ctx, param, value):
    if value is None and not param.required:
        return None
    try:
        return int(value)
    except ValueError:
        raise click.BadParameter(f"{param.name} should be int")


def __ensure_text(ctx, param, value):
    if value is None and not param.required:
        return None
    if isinstance(value, bytes):
        value = value.decode()
    return value


def __load_phantom_private_key(ctx, param, value):
    if ctx.get_parameter_source(param.name).name != "ENVIRONMENT":
        with open(value, "rb") as f:
            value = f.read().strip()

    # Validate the key loads
    serialization.load_pem_private_key(value, password=None)

    return value


def __load_phantom_secret_key(ctx, param, value):
    if ctx.get_parameter_source(param.name).name == "ENVIRONMENT":
        return value

    with open(value, "rb") as f:
        value = f.read().strip()
    m = re.search(
        bytes(r"^SECRET_KEY = '(?P<secret_key>.+)'$"), value, flags=re.MULTILINE
    )
    if not m:
        raise click.BadParameter("Malformed secret key file")
    return m.groupdict()["secret_key"]


def __load_splunk_secret(ctx, param, value):
    if ctx.get_parameter_source(param.name).name != "ENVIRONMENT":
        with open(value, "rb") as f: 
            value = f.read().strip()
    elif isinstance(value, str):
        value = bytes(value, encoding="utf-8")

    return value.strip()


@click.group()
def main():
    pass


@main.command("dbconnect-encrypt")
@click.option(
    "-S",
    "--secret",
    required=True,
    envvar="DBCONNECT_SECRET",
    callback=__load_splunk_secret,
)
@click.option(
    "--password",
    envvar="PASSWORD",
    prompt=True,
    hide_input=True,
    callback=__ensure_text,
)
def dbconnect_encrypt(secret, password):
    """Encrypt password used for dbconnect identity"""
    click.echo(encrypt_dbconnect(secret, password))


@main.command("dbconnect-decrypt")
@click.option(
    "-S",
    "--secret",
    required=True,
    envvar="DBCONNECT_SECRET",
    callback=__load_splunk_secret,
)
@click.option("--ciphertext", envvar="PASSWORD", prompt=True, callback=__ensure_text)
def dbconnect_decrypt(secret, ciphertext):
    """Decrypt password used for dbconnect identity"""
    click.echo(decrypt_dbconnect(secret, ciphertext))


@main.command("phantom-encrypt")
@click.option(
    "-P",
    "--private-key",
    required=True,
    envvar="PHANTOM_PRIVATE_KEY",
    callback=__load_phantom_private_key,
)
@click.option(
    "-S",
    "--secret-key",
    required=True,
    envvar="PHANTOM_SECRET_KEY",
    callback=__load_phantom_secret_key,
)
@click.option(
    "--password",
    envvar="PASSWORD",
    prompt=True,
    hide_input=True,
    callback=__ensure_text,
)
@click.option(
    "-A", "--asset-id", envvar="PHANTOM_ASSET_ID", prompt=True, callback=__ensure_int
)
def phantom_encrypt(private_key, secret_key, password, asset_id):
    """Encrypt password used for Phantom asset"""
    click.echo(encrypt_phantom(private_key, secret_key, password, asset_id))


@main.command("phantom-decrypt")
@click.option(
    "-P",
    "--private-key",
    required=True,
    envvar="PHANTOM_PRIVATE_KEY",
    callback=__load_phantom_private_key,
)
@click.option(
    "-S",
    "--secret-key",
    required=True,
    envvar="PHANTOM_SECRET_KEY",
    callback=__load_phantom_secret_key,
)
@click.option("--ciphertext", envvar="PASSWORD", prompt=True, callback=__ensure_text)
@click.option(
    "-A", "--asset-id", envvar="PHANTOM_ASSET_ID", prompt=True, callback=__ensure_int
)
def phantom_decrypt(private_key, secret_key, ciphertext, asset_id):
    """Decrypt password used for Phantom asset"""
    click.echo(decrypt_phantom(private_key, secret_key, ciphertext, asset_id))


@main.command("splunk-encrypt")
@click.option(
    "-S",
    "--splunk-secret",
    required=True,
    envvar="SPLUNK_SECRET",
    callback=__load_splunk_secret,
)
@click.option("-I", "--iv", envvar="SPLUNK_IV", callback=__ensure_binary)
@click.option(
    "--password",
    envvar="PASSWORD",
    prompt=True,
    hide_input=True,
    callback=__ensure_text,
)
def splunk_encrypt(splunk_secret, password, iv=None):
    """Encrypt password using Splunk 7.2 algorithm"""
    click.echo(encrypt_new(splunk_secret, password, iv))


@main.command("splunk-decrypt")
@click.option(
    "-S",
    "--splunk-secret",
    required=True,
    envvar="SPLUNK_SECRET",
    callback=__load_splunk_secret,
)
@click.option("--ciphertext", envvar="PASSWORD", prompt=True, callback=__ensure_text)
def splunk_decrypt(splunk_secret, ciphertext):
    """Decrypt password using Splunk 7.2 algorithm"""
    click.echo(decrypt(splunk_secret, ciphertext))


@main.command("splunk-legacy-encrypt")
@click.option(
    "-S",
    "--splunk-secret",
    required=True,
    envvar="SPLUNK_SECRET",
    callback=__load_splunk_secret,
)
@click.option(
    "--password",
    envvar="PASSWORD",
    prompt=True,
    hide_input=True,
    callback=__ensure_text,
)
@click.option("--no-salt/--salt", default=False)
def splunk_legacy_encrypt(splunk_secret, password, no_salt):
    """Encrypt password using legacy Splunk algorithm (pre-7.2)"""
    click.echo(encrypt(splunk_secret, password, no_salt))


@main.command("splunk-legacy-decrypt")
@click.option(
    "-S",
    "--splunk-secret",
    required=True,
    envvar="SPLUNK_SECRET",
    callback=__load_splunk_secret,
)
@click.option("--ciphertext", envvar="PASSWORD", prompt=True, callback=__ensure_text)
@click.option("--no-salt/--salt/=", default=False)
def splunk_legacy_decrypt(splunk_secret, ciphertext, no_salt):
    """Decrypt password using legacy Splunk algorithm (pre-7.2)"""
    click.echo(decrypt(splunk_secret, ciphertext, no_salt))

@main.command("dbconnect-legacy-encrypt")
@click.option(
    "-S",
    "--secret",
    required=True,
    envvar="DBCONNECT_SECRET",
    callback=__load_splunk_secret,
)
@click.option(
    "--password",
    envvar="PASSWORD",
    prompt=True,
    hide_input=True,
    callback=__ensure_text,
)
def dbconnect_legacy_encrypt(secret, password):
    """Encrypt password used for dbconnect identity using legacy algorithm"""
    click.echo(encrypt_dbconnect(secret, password, legacy=True))


@main.command("splunk-hash-passwd")
@click.option(
    "--password",
    envvar="PASSWORD",
    prompt=True,
    hide_input=True,
    callback=__ensure_text,
)
def splunk_hash_passwd(password):
    """Generate password hash for use in $SPLUNK_HOME/etc/passwd"""
    click.echo(pcrypt.crypt(password))
