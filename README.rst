splunksecrets - Encrypt and Decrypt Splunk Passwords
====================================================

|Build Status| |codecov.io|

``splunksecrets`` is a tool for working with Splunk secrets offline. It
currently supports encryption and decryption of passwords, but in the
future will support offline recursive conversion of a Splunk
installation from one splunk.secret file to another (e.g. for
synchronizing splunk.secret across your entire distributed
infrastructure).

Installation
------------

``splunksecrets`` can be installed using pip3:

::

   pip3 install splunksecrets

Or, if you're feeling adventurous, can be installed directly from
github:

::

   pip3 install git+https://github.com/HurricaneLabs/splunksecrets.git

Usage
-----

As of version 1.0.0, splunksecrets is broken into subcommands for each
operaton

::

  Usage: splunksecrets [OPTIONS] COMMAND [ARGS]...

  Options:
    --help  Show this message and exit.

  Commands:
    phantom-decrypt        Usage: splunksecrets phantom-decrypt [OPTIONS]
    phantom-encrypt        Usage: splunksecrets phantom-encrypt [OPTIONS]
    splunk-decrypt         Usage: splunksecrets splunk-decrypt [OPTIONS]
    splunk-encrypt         Usage: splunksecrets splunk-encrypt [OPTIONS]
    splunk-hash-passwd     Usage: splunksecrets splunk-hash-passwd [OPTIONS]
    splunk-legacy-decrypt  Usage: splunksecrets splunk-legacy-decrypt...
    splunk-legacy-encrypt  Usage: splunksecrets splunk-legacy-encrypt...

You can find details of the usage of each subcommand by running the command
followed by ``--help``.

- **phantom-encrypt** and **phantom-decrypt** are for interacting with
  credentials stored in the Phantom database
- **splunk-encrypt** and **splunk-decrypt** are for interacting with
  credentials from Splunk 7.2 or newer
- **splunk-legacy-encrypt** and **splunk-legacy-decrypt** are for interacting
  with credentials from Splunk versions below 7.2
- **splunk-hash-passwd** is for generating Splunk local user password hashes
  for use in ``$SPLUNK_HOME/etc/passwd``

Encryption Schemes
------------------

Splunk passwd hashes
~~~~~~~~~~~~~~~~~~~~

Splunk password hashes are not, strictly speaking, encrypted. They're
hashed using the standard Unix ``crypt`` function. The ``$6$`` indicates
that SHA-512 hashing algorithm is used. Details on SHA-crypt can be
found `here <https://akkadia.org/drepper/SHA-crypt.txt>`__.

Splunk pre-7.2
~~~~~~~~~~~~~~

Splunk prior to 7.2 used RC4 encryption for secrets, indicated in
configuration files by ``$1$`` in the encrypted password. The plaintext
password is XOR'ed with a static salt (``DEFAULTSA``) and then RC4
encrypted using the first 16-bytes of ``splunk.secret`` as the key. The
resulting ciphertext is base64-encoded and prepended with ``$1$`` to
produce the encrypted password seen in the configuration files.

Splunk 7.2
~~~~~~~~~~

Starting in Splunk 7.2, AES256-GCM is used for encryption of secrets,
indicated in configuration files by ``$7$`` in the encrypted password.
The ``PBKDF2`` algorithm is used to derive an encryption key from all
254 bytes of ``splunk.secret`` (the newline character is stripped from
the end of the file), using a static salt of ``disk-encryption`` and a
single iteration. This 256-bit key is then used as the encryption key
for AES256-GCM, with a 16-byte randomly generated initialization vector.
The encryption produces both the ciphertext as well as a "tag" that is
used as part of integrity verification. The iv, ciphertext, and tag (in
that order) are concatenated, base64-encoded, and prepended with ``$7$``
to produce the encrypted password seen in the configuration files.

Phantom
~~~~~~~

Phantom stores encrypted credentials in it's internal database as part
of the JSON blob in the ``configuration`` column of the asset table.
These credentials are encrypted using AES256-CBC and are stored
base64-encoded. A SHA256 hash is generated using the public modulus of
the Phantom RSA private key (located at
``/opt/phantom/keystore/private_key.pem``) concatenated with the
Django ``SECRET_KEY`` (found in
``/opt/phantom/www/phantom_ui/secret_key.py``) - this hash is used as
the key for the AES encryption. A SHA1 hash is generated using the
``id`` of the asset from the ``asset`` table - this hash is used as
the initialization vector (``iv``) for the AES encryption. The password
to be encrypted is padded using PKCS7 padding prior to encryption.

Known Issues
------------

- If the splunk secret and an encrypted password don't match, one of
  two things will happen - either you'll get gibberish output, or a
  Python traceback. At some point, we'll hopefully have better error
  checking for this.

Version History
---------------

Version 1.0.0rc1 (2021-05-19)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- New CLI interface that breaks each operation into its own subcommand
- CLI interface supports passing path to key files (splunk.secret,
  private_key.pem, and secret_key.py) via arguments, or file contents
  via environment variables
- Add initial support for encryption/decryption of Phantom asset
  credentials (thanks swoops)

Version 0.5.0 (2020-06-23)
~~~~~~~~~~~~~~~~~~~~~~~~~~
- Add support for passing a path to splunk.secret, the splunk.secret
  contents, and the password/password hash via environment variables
  (thanks hanswurscht)
- Added error output when trying to decrypt user passwords

Version 0.4.3 (2020-02-17)
~~~~~~~~~~~~~~~~~~~~~~~~~~

- Correct an issue when splunk secret is too long. Splunk handles this
  by truncating splunk.secret to 254 bytes, so we now do the same
  (thanks nbertram)
- Added error checking in case, somehow, splunk secret is too short.

Version 0.4.2 (2019-09-29)
~~~~~~~~~~~~~~~~~~~~~~~~~~

- Add handling for incorrectly padded (but otherwise correct) password
  strings as a convenience (thanks rafrey-his)

Version 0.4.1 (2019-09-11)
~~~~~~~~~~~~~~~~~~~~~~~~~~

- Fix an issue in Python 3 when using ``--splunk-secret-text`` (thanks
  Joeboyc2)

Version 0.4.0 (2019-03-25)
~~~~~~~~~~~~~~~~~~~~~~~~~~

- Add ``--hash-passwd`` flag for generating Splunk password hashes

Version 0.3.1 (2019-02-06)
~~~~~~~~~~~~~~~~~~~~~~~~~~

- Fix bug when a character in the password was the same as the salt
  character
- Add ``--splunk-secret-text`` and ``--password`` arguments for
  non-interactive use (thanks nadidsky)

Version 0.3.0 (2019-01-26)
~~~~~~~~~~~~~~~~~~~~~~~~~~

- Add ``--nosalt`` flag for pre-7.2 passwords that are not salted, such
  as ``sslPassword`` (thanks duckfez)

Version 0.2.1 (2018-10-27)
~~~~~~~~~~~~~~~~~~~~~~~~~~

- Cosmetic release to update metadata on PyPI

Version 0.2.0 (2018-10-24)
~~~~~~~~~~~~~~~~~~~~~~~~~~

- Add support for Splunk 7.2

Version 0.1.0 (2018-10-08)
~~~~~~~~~~~~~~~~~~~~~~~~~~

- Initial release
- Support Splunk < 7.2

License Info
------------

The MIT License (MIT)

Copyright (c) 2020 Hurricane Labs LLC

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

.. |Build Status| image:: https://travis-ci.org/HurricaneLabs/splunksecrets.svg?branch=master
   :target: https://travis-ci.org/HurricaneLabs/splunksecrets
.. |codecov.io| image:: https://codecov.io/gh/HurricaneLabs/splunksecrets/branch/master/graph/badge.svg
   :target: https://codecov.io/gh/HurricaneLabs/splunksecrets
