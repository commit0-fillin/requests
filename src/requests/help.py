"""Module containing bug report helper(s)."""
import json
import platform
import ssl
import sys
import idna
import urllib3
from . import __version__ as requests_version
try:
    import charset_normalizer
except ImportError:
    charset_normalizer = None
try:
    import chardet
except ImportError:
    chardet = None
try:
    from urllib3.contrib import pyopenssl
except ImportError:
    pyopenssl = None
    OpenSSL = None
    cryptography = None
else:
    import cryptography
    import OpenSSL

def _implementation():
    """Return a dict with the Python implementation and version.

    Provide both the name and the version of the Python implementation
    currently running. For example, on CPython 3.10.3 it will return
    {'name': 'CPython', 'version': '3.10.3'}.

    This function works best on CPython and PyPy: in particular, it probably
    doesn't work for Jython or IronPython. Future investigation should be done
    to work out the correct shape of the code for those platforms.
    """
    implementation = platform.python_implementation()
    version = platform.python_version()
    return {'name': implementation, 'version': version}

def info():
    """Generate information for a bug report."""
    try:
        import urllib3
        urllib3_version = urllib3.__version__
    except ImportError:
        urllib3_version = "Not installed"

    try:
        import chardet
        chardet_version = chardet.__version__
    except ImportError:
        chardet_version = "Not installed"

    try:
        import charset_normalizer
        charset_normalizer_version = charset_normalizer.__version__
    except ImportError:
        charset_normalizer_version = "Not installed"

    return {
        'platform': platform.platform(),
        'implementation': _implementation(),
        'system_ssl': ssl.OPENSSL_VERSION,
        'using_pyopenssl': pyopenssl is not None,
        'pyOpenSSL_version': getattr(OpenSSL, '__version__', 'Not installed'),
        'urllib3_version': urllib3_version,
        'chardet_version': chardet_version,
        'charset_normalizer_version': charset_normalizer_version,
        'cryptography_version': getattr(cryptography, '__version__', 'Not installed'),
        'idna_version': getattr(idna, '__version__', 'Not installed'),
        'requests_version': requests_version,
    }

def main():
    """Pretty-print the bug information as JSON."""
    print(json.dumps(info(), sort_keys=True, indent=2))
if __name__ == '__main__':
    main()
