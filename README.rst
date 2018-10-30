splunksecrets - Encrypt and Decrypt Splunk Passwords
================================================================================

|Build Status| |codecov.io|

``splunksecrets`` is a tool for working with Splunk secrets offline. It currently
supports encryption and decryption of passwords, but in the future will support
offline recursive conversion of a Splunk installation from one splunk.secret
file to another (e.g. for synchronizing splunk.secret across your entire
distributed infrastructure).

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

::

    usage: splunksecrets [-h] --splunk-secret SPLUNK_SECRET [-D] [--new]

    optional arguments:
      -h, --help            show this help message and exit
      --splunk-secret SPLUNK_SECRET
      -D, --decrypt
      --new

-  Use ``--new`` when encrypting/decrypting Splunk 7.2 secrets (indicated by ``$7$``)

Encryption Schemes
------------------

Splunk pre-7.2
~~~~~~~~~~~~~~

Splunk prior to 7.2 used RC4 encryption for secrets, indicated in configuration files by ``$1$``
in the encrypted password. The plaintext password is XOR'ed with a static salt (``DEFAULTSA``) and
then RC4 encrypted using the first 16-bytes of ``splunk.secret`` as the key. The resulting
ciphertext is base64-encoded and prepended with ``$1$`` to produce the encrypted password seen in
the configuration files.

Splunk 7.2
~~~~~~~~~~

Starting in Splunk 7.2, AES256-GCM is used for encryption of secrets, indicated in configuration
files by ``$7$`` in the encrypted password. The ``PBKDF2`` algorithm is used to derive an
encryption key from all 254 bytes of ``splunk.secret`` (the newline character is stripped from the
end of the file), using a static salt of ``disk-encryption`` and a single iteration. This 256-bit
key is then used as the encryption key for AES256-GCM, with a 16-byte randomly generated
initialization vector. The encryption produces both the ciphertext as well as a "tag" that is
used as part of integrity verification. The iv, ciphertext, and tag (in that order) are
concatenated, base64-encoded, and prepended with ``$7$`` to produce the encrypted password seen in
the configuration files.

Known Issues
------------
-  None so far!

Version History
---------------

Version 0.2.1 (2018-10-27)
~~~~~~~~~~~~~~~~~~~~~~~~~~

- Cosmetic release to update metadata on PyPI

Version 0.2.0 (2018-10-24)
~~~~~~~~~~~~~~~~~~~~~~~~~~

- Add support for Splunk 7.2

Version 0.1.0 (2018-10-08)
~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Initial release
-  Support Splunk < 7.2

License Info
------------

The MIT License (MIT)

Copyright (c) 2018 Hurricane Labs LLC

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

.. |Build Status| image:: https://travis-ci.org/HurricaneLabs/splunksecrets.svg?branch=master
    :target: https://travis-ci.org/HurricaneLabs/splunksecrets
.. |codecov.io| image:: https://codecov.io/gh/HurricaneLabs/splunksecrets/branch/master/graph/badge.svg
    :target: https://codecov.io/gh/HurricaneLabs/splunksecrets
