"""
requests.auth
~~~~~~~~~~~~~

This module contains the authentication handlers for Requests.
"""
import hashlib
import os
import re
import threading
import time
import warnings
from base64 import b64encode
from ._internal_utils import to_native_string
from .compat import basestring, str, urlparse
from .cookies import extract_cookies_to_jar
from .utils import parse_dict_header
CONTENT_TYPE_FORM_URLENCODED = 'application/x-www-form-urlencoded'
CONTENT_TYPE_MULTI_PART = 'multipart/form-data'

def _basic_auth_str(username, password):
    """Returns a Basic Auth string."""
    auth = f"{username}:{password}"
    return f"Basic {b64encode(auth.encode('utf-8')).decode('ascii')}"

class AuthBase:
    """Base class that all auth implementations derive from"""

    def __call__(self, r):
        raise NotImplementedError('Auth hooks must be callable.')

class HTTPBasicAuth(AuthBase):
    """Attaches HTTP Basic Authentication to the given Request object."""

    def __init__(self, username, password):
        self.username = to_native_string(username)
        self.password = to_native_string(password)

    def __eq__(self, other):
        return all([
            isinstance(other, HTTPBasicAuth),
            self.username == getattr(other, 'username', None),
            self.password == getattr(other, 'password', None)
        ])

    def __ne__(self, other):
        return not self == other

    def __call__(self, r):
        r.headers['Authorization'] = _basic_auth_str(self.username, self.password)
        return r

class HTTPProxyAuth(HTTPBasicAuth):
    """Attaches HTTP Proxy Authentication to a given Request object."""

    def __call__(self, r):
        r.headers['Proxy-Authorization'] = _basic_auth_str(self.username, self.password)
        return r

class HTTPDigestAuth(AuthBase):
    """Attaches HTTP Digest Authentication to the given Request object."""

    def __init__(self, username, password):
        self.username = username
        self.password = password
        self._thread_local = threading.local()
        self._thread_local.last_nonce = ''
        self._thread_local.nonce_count = 0
        self._thread_local.chal = {}
        self._thread_local.pos = None
        self._thread_local.num_401_calls = 1

    def build_digest_header(self, method, url):
        """
        :rtype: str
        """
        realm = self._thread_local.chal.get('realm')
        nonce = self._thread_local.chal.get('nonce')
        qop = self._thread_local.chal.get('qop')
        algorithm = self._thread_local.chal.get('algorithm')
        opaque = self._thread_local.chal.get('opaque')

        if algorithm is None:
            _algorithm = 'MD5'
        else:
            _algorithm = algorithm.upper()

        if _algorithm == 'MD5' or _algorithm == 'MD5-SESS':
            def md5_utf8(x):
                if isinstance(x, str):
                    x = x.encode('utf-8')
                return hashlib.md5(x).hexdigest()
            hash_utf8 = md5_utf8
        elif _algorithm == 'SHA':
            def sha_utf8(x):
                if isinstance(x, str):
                    x = x.encode('utf-8')
                return hashlib.sha1(x).hexdigest()
            hash_utf8 = sha_utf8

        KD = lambda s, d: hash_utf8("%s:%s" % (s, d))

        if hash_utf8 is None:
            return None

        entdig = None
        p_parsed = urlparse(url)
        path = p_parsed.path or "/"
        if p_parsed.query:
            path += "?" + p_parsed.query

        A1 = '%s:%s:%s' % (self.username, realm, self.password)
        A2 = '%s:%s' % (method, path)

        HA1 = hash_utf8(A1)
        HA2 = hash_utf8(A2)

        if nonce == self._thread_local.last_nonce:
            self._thread_local.nonce_count += 1
        else:
            self._thread_local.nonce_count = 1
        ncvalue = '%08x' % self._thread_local.nonce_count
        s = str(self._thread_local.nonce_count).encode('utf-8')
        s += nonce.encode('utf-8')
        s += time.ctime().encode('utf-8')
        s += os.urandom(8)

        cnonce = (hashlib.sha1(s).hexdigest()[:16])
        if _algorithm == 'MD5-SESS':
            HA1 = hash_utf8('%s:%s:%s' % (HA1, nonce, cnonce))

        if qop is None:
            respdig = KD(HA1, "%s:%s" % (nonce, HA2))
        elif qop == 'auth' or 'auth' in qop.split(','):
            noncebit = "%s:%s:%s:%s:%s" % (nonce, ncvalue, cnonce, 'auth', HA2)
            respdig = KD(HA1, noncebit)
        else:
            return None

        self._thread_local.last_nonce = nonce

        base = 'username="%s", realm="%s", nonce="%s", uri="%s", ' \
               'response="%s"' % (self.username, realm, nonce, path, respdig)
        if opaque:
            base += ', opaque="%s"' % opaque
        if algorithm:
            base += ', algorithm="%s"' % algorithm
        if entdig:
            base += ', digest="%s"' % entdig
        if qop:
            base += ', qop="auth", nc=%s, cnonce="%s"' % (ncvalue, cnonce)

        return 'Digest %s' % (base)

    def handle_redirect(self, r, **kwargs):
        """Reset num_401_calls counter on redirects."""
        if r.is_redirect:
            self._thread_local.num_401_calls = 1

    def handle_401(self, r, **kwargs):
        """
        Takes the given response and tries digest-auth, if needed.

        :rtype: requests.Response
        """
        if not 400 <= r.status_code < 500:
            self._thread_local.num_401_calls = 1
            return r

        if self._thread_local.pos is not None:
            r.request.body.seek(self._thread_local.pos)
        s_auth = r.headers.get('www-authenticate', '')

        if 'digest' in s_auth.lower() and self._thread_local.num_401_calls < 2:
            self._thread_local.num_401_calls += 1
            pat = re.compile(r'digest ', flags=re.IGNORECASE)
            self._thread_local.chal = parse_dict_header(pat.sub('', s_auth, count=1))

            r.content
            r.close()
            prep = r.request.copy()
            extract_cookies_to_jar(prep._cookies, r.request, r.raw)
            prep.prepare_cookies(prep._cookies)

            prep.headers['Authorization'] = self.build_digest_header(
                prep.method, prep.url)
            _r = r.connection.send(prep, **kwargs)
            _r.history.append(r)
            _r.request = prep

            return _r

        self._thread_local.num_401_calls = 1
        return r

    def __call__(self, r):
        self.init_per_thread_state()
        if self._thread_local.last_nonce:
            r.headers['Authorization'] = self.build_digest_header(r.method, r.url)
        try:
            self._thread_local.pos = r.body.tell()
        except AttributeError:
            self._thread_local.pos = None
        r.register_hook('response', self.handle_401)
        r.register_hook('response', self.handle_redirect)
        self._thread_local.num_401_calls = 1
        return r

    def __eq__(self, other):
        return all([
            isinstance(other, HTTPDigestAuth),
            self.username == getattr(other, 'username', None),
            self.password == getattr(other, 'password', None)
        ])

    def __ne__(self, other):
        return not self == other
