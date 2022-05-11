"""
 Based on code from "I never signed up for this! Privacy implications of email
 tracking" by Steve Englehardt, Jeffrey Han, Arvind Narayanan.
 Proceedings on Privacy Enhancing Technologies 2018.1 (2018): 109-126.
"""

import cProfile
import html
from urllib.parse import urlparse, parse_qs, quote_plus
from Crypto.Hash import MD2
from collections import defaultdict
from http import cookies as ck
# import hackercodecs  # noqa
import hashlib
# import pyblake2
import urllib
import sha3
import mmh3
# import mmhash
import base64
import base58
import zlib
import json
import re
from lzstring import LZString
from collections import defaultdict

# DELIMITERS = re.compile('[&|\,]')
DELIMITERS = re.compile('[&|\,]|%s|%s' % (quote_plus("="), quote_plus("&")))
EXTENSION_RE = re.compile('\.[A-Za-z]{2,4}$')
ENCODING_LAYERS = 3
ENCODINGS_NO_ROT = [
    'base16',
    'base32',
    'base58',
    'base64',
    'urlencode',
    # 'yenc',
    'entity',
    'deflate',
    'zlib',
    'gzip',
    'lzstring',
    'custom_map_1'
    ]

LIKELY_ENCODINGS = [
    'base64',
    'urlencode',
    'entity',
    'lzstring',
    'custom_map_1'
    ]

HASHES = ['md2', 'md4', 'md5', 'sha1', 'sha256', 'sha224', 'sha384',
          'sha512', 'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512',
          # 'mmh2', 'mmh2_unsigned',
          # 'mmh3_32',
          'mmh3_64_1', 'mmh3_64_2', 'mmh3_128',
          'ripemd160',
          'whirlpool',
          'sha_salted_1'
          # , 'blake2b', 'blake2s'
          ]

LIKELY_HASHES = [
    'md5',
    'sha1',
    'sha256',
    'sha512',
    'sha_salted_1'
    ]


def get_path_from_url(url):
    try:
        return url.split(urlparse(url).netloc, 1)[-1]
    except Exception as exc:
        print("Cannot parse url %s %s" % (url, exc))
        return ""


CUSTOM_MAP_IN = "kibp8A4EWRMKHa7gvyz1dOPt6UI5xYD3nqhVwZBXfCcFeJmrLN20lS9QGsjTuo"
CUSTOM_MAP_OUT = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

CUSTOM_MAP_ENC = str.maketrans(CUSTOM_MAP_IN, CUSTOM_MAP_OUT)
CUSTOM_MAP_DEC = str.maketrans(CUSTOM_MAP_OUT, CUSTOM_MAP_IN)


def custom_map_enc(_string):
    return _string.translate(CUSTOM_MAP_ENC)


def custom_map_dec(_string):
    return _string.translate(CUSTOM_MAP_DEC)


class Hasher():
    def __init__(self):
        # Define Supported hashes
        hashes = dict()
        hashes['md2'] = lambda x: self._get_md2_hash(x.encode())
        hashes['md4'] = lambda x: self._get_hashlib_hash('md4', x.encode())
        hashes['md5'] = lambda x: hashlib.md5(x.encode()).hexdigest()
        hashes['sha'] = lambda x: self._get_hashlib_hash('sha', x)
        hashes['sha1'] = lambda x: hashlib.sha1(x.encode()).hexdigest()
        hashes['sha256'] = lambda x: hashlib.sha256(x.encode()).hexdigest()
        hashes['sha224'] = lambda x: hashlib.sha224(x.encode()).hexdigest()
        hashes['sha384'] = lambda x: hashlib.sha384(x.encode()).hexdigest()
        hashes['sha512'] = lambda x: hashlib.sha512(x.encode()).hexdigest()
        hashes['sha3_224'] = lambda x: sha3.sha3_224(x.encode()).hexdigest()
        hashes['sha3_256'] = lambda x: sha3.sha3_256(x.encode()).hexdigest()
        hashes['sha3_384'] = lambda x: sha3.sha3_384(x.encode()).hexdigest()
        hashes['sha3_512'] = lambda x: sha3.sha3_512(x.encode()).hexdigest()
        # hashes['mmh2'] = lambda x: str(mmhash.get_hash(x))
        # hashes['mmh2_unsigned'] = lambda x: str(mmhash.get_unsigned_hash(x))
        # hashes['mmh3_32'] = lambda x: str(mmh3.hash(x))
        hashes['mmh3_64_1'] = lambda x: str(mmh3.hash64(x)[0])
        hashes['mmh3_64_2'] = lambda x: str(mmh3.hash64(x)[1])
        hashes['mmh3_128'] = lambda x: str(mmh3.hash128(x))
        hashes['ripemd160'] = lambda x: self._get_hashlib_hash('ripemd160', x.encode())
        hashes['whirlpool'] = lambda x: self._get_hashlib_hash('whirlpool', x.encode())
        hashes['sha_salted_1'] = lambda x: hashlib.sha256(
            x.encode() + 'QX4QkKEU'.encode()).hexdigest()

        # hashes['blake2b'] = lambda x: pyblake2.blake2b(x).hexdigest()
        # hashes['blake2s'] = lambda x: pyblake2.blake2s(x).hexdigest()
        # hashes['crc32'] = lambda x: str(zlib.crc32(x))
        # hashes['adler32'] = lambda x: str(zlib.adler32(x))

        self._hashes = hashes
        self.hashes_and_checksums = self._hashes.keys()
        self.supported_hashes = HASHES

    def _get_hashlib_hash(self, name, string):
        """Use for hashlib hashes that don't have a shortcut"""
        hasher = hashlib.new(name)
        hasher.update(string)
        return hasher.hexdigest()

    def _get_md2_hash(self, string):
        """Compute md2 hash"""
        md2 = MD2.new()
        md2.update(string)
        return md2.hexdigest()

    def get_hash(self, hash_name, string):
        """Compute the desired hash"""
        return self._hashes[hash_name](string)


class Encoder():
    def __init__(self):
        # Define supported encodings
        encodings = dict()
        encodings['base16'] = lambda x: base64.b16encode(x.encode())
        encodings['base32'] = lambda x: base64.b32encode(x.encode())
        encodings['base58'] = lambda x: base58.b58encode(x.encode())
        encodings['base64'] = lambda x: base64.b64encode(x.encode())
        encodings['urlencode'] = lambda x: urllib.parse.quote_plus(x)
        encodings['deflate'] = lambda x: self._compress_with_zlib('deflate', x.encode())
        encodings['zlib'] = lambda x: self._compress_with_zlib('zlib', x.encode())
        encodings['gzip'] = lambda x: self._compress_with_zlib('gzip', x.encode())
        encodings['json'] = lambda x: json.dumps(x)
        encodings['binary'] = lambda x: x.encode('bin')
        # encodings['entity'] = lambda x: x.encode('entity')
        encodings['entity'] = lambda x: html.escape(x)
        encodings['rot1'] = lambda x: x.encode('rot1')
        encodings['rot10'] = lambda x: x.encode('rot10')
        encodings['rot11'] = lambda x: x.encode('rot11')
        encodings['rot12'] = lambda x: x.encode('rot12')
        encodings['rot13'] = lambda x: x.encode('rot13')
        encodings['rot14'] = lambda x: x.encode('rot14')
        encodings['rot15'] = lambda x: x.encode('rot15')
        encodings['rot16'] = lambda x: x.encode('rot16')
        encodings['rot17'] = lambda x: x.encode('rot17')
        encodings['rot18'] = lambda x: x.encode('rot18')
        encodings['rot19'] = lambda x: x.encode('rot19')
        encodings['rot2'] = lambda x: x.encode('rot2')
        encodings['rot20'] = lambda x: x.encode('rot20')
        encodings['rot21'] = lambda x: x.encode('rot21')
        encodings['rot22'] = lambda x: x.encode('rot22')
        encodings['rot23'] = lambda x: x.encode('rot23')
        encodings['rot24'] = lambda x: x.encode('rot24')
        encodings['rot25'] = lambda x: x.encode('rot25')
        encodings['rot3'] = lambda x: x.encode('rot3')
        encodings['rot4'] = lambda x: x.encode('rot4')
        encodings['rot5'] = lambda x: x.encode('rot5')
        encodings['rot6'] = lambda x: x.encode('rot6')
        encodings['rot7'] = lambda x: x.encode('rot7')
        encodings['rot8'] = lambda x: x.encode('rot8')
        encodings['rot9'] = lambda x: x.encode('rot9')
        encodings['lzstring'] = LZString.compressToEncodedURIComponent
        encodings['custom_map_1'] = custom_map_enc
        # encodings['yenc'] = lambda x: x.encode('yenc')
        self._encodings = encodings
        self.supported_encodings = self._encodings.keys()

    def _compress_with_zlib(self, compression_type, string, level=6):
        """Compress in one of the zlib supported formats: zlib, gzip, or deflate.
        For a description see: http://stackoverflow.com/a/22311297/6073564
        """
        if compression_type == 'deflate':
            compressor = zlib.compressobj(level, zlib.DEFLATED,
                                          -zlib.MAX_WBITS)
        elif compression_type == 'zlib':
            compressor = zlib.compressobj(level, zlib.DEFLATED,
                                          zlib.MAX_WBITS)
        elif compression_type == 'gzip':
            compressor = zlib.compressobj(level, zlib.DEFLATED,
                                          zlib.MAX_WBITS | 16)
        else:
            raise ValueError("Unsupported zlib compression format %s." %
                             compression_type)
        return compressor.compress(string) + compressor.flush()

    def encode(self, encoding, string):
        """Encode `string` in desired `encoding`"""
        return self._encodings[encoding](string)


class DecodeException(Exception):
    def __init__(self, message, error):
        super(DecodeException, self).__init__(message)
        self.error = error


class Decoder():
    def __init__(self):
        # Define supported encodings
        decodings = dict()
        decodings['base16'] = lambda x: base64.b16decode(x)
        decodings['base32'] = lambda x: base64.b32decode(x)
        decodings['base58'] = lambda x: base58.b58decode(x)
        decodings['base64'] = lambda x: base64.b64decode(x)
        decodings['urlencode'] = lambda x: urllib.parse.unquote(x)
        decodings['deflate'] = lambda x: self._decompress_with_zlib('deflate',
                                                                    x)
        decodings['zlib'] = lambda x: self._decompress_with_zlib('zlib', x)
        decodings['gzip'] = lambda x: self._decompress_with_zlib('gzip', x)
        decodings['json'] = lambda x: json.loads(x)
        decodings['binary'] = lambda x: x.decode('bin')
        decodings['entity'] = lambda x: x.decode('entity')
        decodings['rot1'] = lambda x: x.decode('rot1')
        decodings['rot10'] = lambda x: x.decode('rot10')
        decodings['rot11'] = lambda x: x.decode('rot11')
        decodings['rot12'] = lambda x: x.decode('rot12')
        decodings['rot13'] = lambda x: x.decode('rot13')
        decodings['rot14'] = lambda x: x.decode('rot14')
        decodings['rot15'] = lambda x: x.decode('rot15')
        decodings['rot16'] = lambda x: x.decode('rot16')
        decodings['rot17'] = lambda x: x.decode('rot17')
        decodings['rot18'] = lambda x: x.decode('rot18')
        decodings['rot19'] = lambda x: x.decode('rot19')
        decodings['rot2'] = lambda x: x.decode('rot2')
        decodings['rot20'] = lambda x: x.decode('rot20')
        decodings['rot21'] = lambda x: x.decode('rot21')
        decodings['rot22'] = lambda x: x.decode('rot22')
        decodings['rot23'] = lambda x: x.decode('rot23')
        decodings['rot24'] = lambda x: x.decode('rot24')
        decodings['rot25'] = lambda x: x.decode('rot25')
        decodings['rot3'] = lambda x: x.decode('rot3')
        decodings['rot4'] = lambda x: x.decode('rot4')
        decodings['rot5'] = lambda x: x.decode('rot5')
        decodings['rot6'] = lambda x: x.decode('rot6')
        decodings['rot7'] = lambda x: x.decode('rot7')
        decodings['rot8'] = lambda x: x.decode('rot8')
        decodings['rot9'] = lambda x: x.decode('rot9')
        decodings['yenc'] = lambda x: x.decode('yenc')
        decodings['lzstring'] = LZString.decompressFromEncodedURIComponent
        decodings['custom_map_1'] = custom_map_dec
        self._decodings = decodings
        self.supported_encodings = self._decodings.keys()

    def _decompress_with_zlib(self, compression_type, string, level=9):
        """Compress in one of the zlib supported formats: zlib, gzip, or deflate.
        For a description see: http://stackoverflow.com/a/22311297/6073564
        """
        if compression_type == 'deflate':
            return zlib.decompress(string, -zlib.MAX_WBITS)
        elif compression_type == 'zlib':
            return zlib.decompress(string, zlib.MAX_WBITS)
        elif compression_type == 'gzip':
            return zlib.decompress(string, zlib.MAX_WBITS | 16)
        else:
            raise ValueError("Unsupported zlib compression format %s." %
                             compression_type)

    def decode_error(self):
        """Catch-all error for all supported decoders"""

    def decode(self, encoding, string):
        """Decode `string` encoded by `encoding`"""
        try:
            return self._decodings[encoding](string)
        except Exception as e:
            raise DecodeException(
                'Error while trying to decode %s' % encoding,
                e
            )


class LeakDetector():
    def __init__(self, search_strings, precompute_hashes=True, hash_set=None,
                 hash_layers=2, precompute_encodings=True, encoding_set=None,
                 encoding_layers=2, debugging=False):
        """LeakDetector searches URL, POST bodies, and cookies for leaks.

        The detector is constructed with a set of search strings (given by
        the `search_strings` parameters. It has several methods to check for
        leaks containing these strings in URLs, POST bodies, and cookie header
        strings.

        Parameters
        ==========
        search_strings : list
            LeakDetector will search for leaks containing any item in this list
        precompute_hashes : bool
            Set to `True` to include precomputed hashes in the candidate set.
        hash_set : list
            List of hash functions to use when building the set of candidate
            strings.
        hash_layers : int
            The detector will find instances of `search_string` iteratively
            hashed up to `hash_layers` times by any combination of supported
            hashes.
        precompute_encodings : bool
            Set to `True` to include precomputed encodings in the candidate set
        encoding_set : list
            List of encodings to use when building the set of candidate
            strings.
        encoding_layers : int
            The detector will find instances of `search_string` iteratively
            encoded up to `encoding_layers` times by any combination of
            supported encodings.
        debugging : bool
            Set to `True` to enable a verbose output.
        """
        # print(search_strings)
        self.search_strings = search_strings
        self._min_length = min([len(x) for x in search_strings])
        self._hasher = Hasher()
        self._hash_set = hash_set
        self._hash_layers = hash_layers
        self._encoder = Encoder()
        self._encoding_set = encoding_set
        self._encoding_layers = encoding_layers
        self._decoder = Decoder()
        self._precompute_pool = dict()
        self._precompute_pool_by_layer = defaultdict(dict)
        # If hash/encoding sets aren't specified, use all available.
        if self._hash_set is None:
            self._hash_set = self._hasher.supported_hashes
        if self._encoding_set is None:
            self._encoding_set = self._encoder.supported_encodings
        self._build_precompute_pool(precompute_hashes, precompute_encodings)
        self._debugging = debugging
        self._checked = defaultdict(set)  # set of already searched strings per layer

    def _compute_hashes(self, string, layers, prev_hashes=tuple()):
        """Returns all iterative hashes of `string` up to the
        specified number of `layers`"""
        for h in self._hasher.supported_hashes:
            hashed_string = self._hasher.get_hash(h, string)
            if hashed_string == string:  # skip no-ops
                continue
            hash_stack = (h,) + prev_hashes
            self._precompute_pool[hashed_string] = hash_stack
            if layers > 1:
                self._compute_hashes(hashed_string, layers-1, hash_stack)

    def _compute_encodings(self, string, layers, prev_encodings=tuple()):
        """Returns all iterative encodings of `string` up to the
        specified number of `layers`"""
        for enc in self._encoding_set:
            try:
                encoded_string = self._encoder.encode(enc, string).decode()
            except AttributeError:
                encoded_string = self._encoder.encode(enc, string)
            except UnicodeDecodeError:
                encoded_string = str(self._encoder.encode(enc, string))

            if encoded_string == string:  # skip no-ops
                continue
            encoding_stack = (enc,) + prev_encodings
            self._precompute_pool[encoded_string] = encoding_stack
            if layers > 1:
                self._compute_encodings(encoded_string, layers-1,
                                        encoding_stack)

    def _build_precompute_pool(self, precompute_hashes, precompute_encodings):
        """Build a pool of hashes for the given search string"""
        seed_strings = list()
        for string in self.search_strings:
            seed_strings.append(string)
            if string.startswith('http'):
                continue
            all_lower = string.lower()
            if all_lower != string:
                seed_strings.append(string.lower())
            all_upper = string.upper()
            if all_upper != string:
                seed_strings.append(string.upper())

        strings = list()
        for string in seed_strings:
            strings.append(string)
            ENABLE_USERNAME_MATCH = False
            # If the search string appears to be an email address, we also want
            # to include just the username portion of the URL, and the address
            # and username with any '.'s removed from the username (since these
            # are optional in Gmail).
            if ENABLE_USERNAME_MATCH and '@' in string:
                parts = string.rsplit('@')
                if len(parts) == 2:
                    uname, domain = parts
                    strings.append(uname)
                    strings.append(re.sub('\.', '', uname))
                    strings.append(re.sub('\.', '', uname) + '@' + domain)
                # Domain searches have too many false positives
                # strings.append(parts[1])
                # strings.append(parts[1].rsplit('.', 1)[0])
            # The URL tokenizer strips file extensions. So if our search string
            # has a file extension we should also search for a stripped version
            if re.match(EXTENSION_RE, string):
                strings.append(re.sub(EXTENSION_RE, '', string))
        for string in strings:
            self._precompute_pool[string] = (string,)
        self._min_length = min([len(x) for x in list(self._precompute_pool)])
        initial_items = list(self._precompute_pool.items())
        if precompute_hashes:
            for string, name in initial_items:
                self._compute_hashes(string, self._hash_layers, name)
        if precompute_encodings:
            for string, name in initial_items:
                self._compute_encodings(string, self._encoding_layers, name)
        for value, encodings in self._precompute_pool.items():
            self._precompute_pool_by_layer[len(encodings)][encodings] = value.encode('utf8')
            # print('_precompute_pool', k, v)

    def _split_on_delims(self, string, rv_parts, rv_named):
        """Splits a string on several delimiters"""
        if string == '':
            return
        parts = set(re.split(DELIMITERS, string))

        if '' in parts:
            parts.remove('')
        for part in parts:
            if part == '':
                continue
            count = part.count('=')
            if count != 1:
                rv_parts.add(part)
            if count == 0:
                continue
            n, k = part.split('=', 1)
            if len(n) > 0 and len(k) > 0:
                rv_named.add((n, k))
            else:
                rv_parts.add(part)
        if self._debugging:
            if self._debugging:
                print('RV PARTS: ', rv_parts)

    def check_if_in_precompute_pool(self, string):
        """Returns a tuple that lists the (possibly layered) hashes or
        encodings that result in input string
        """
        try:
            return self._precompute_pool[str(string)]
        except KeyError:
            try:
                if isinstance(string, bytes):
                    return self._precompute_pool[string.decode()]
                return
            except (UnicodeDecodeError, UnicodeEncodeError, KeyError):
                return
        except (UnicodeDecodeError, UnicodeEncodeError, KeyError):
            return

    def check_for_leak(self, string, layers=1, prev_encodings=tuple(),
                       prev=''):
        """Check if given string contains a leak"""
        # Short tokens won't contain email address
        if len(string) < self._min_length:
            return

        if string in self._checked[prev_encodings]:
            return

        self._checked[prev_encodings].add(string)  # add to already checked

        if self._debugging:
            if isinstance(string, bytes):
                decoded_string = string.decode(errors="ignore")
                print('Will search: %s (layer: %d) prev_encodings: %s'
                      % (decoded_string, layers, prev_encodings))
            else:
                print('Will search: %s (layer: %d) prev_encodings: %s'
                      % (string, layers, prev_encodings))
            try:
                if "cosic" in str(string) or "cosic" in string.decode():
                    print('SUSPICIOUS-(cosic): %s (layer: %d)' % (string, layers))
            except Exception:
                pass

        substr_results = self.substring_search(
            string, max_layers=self._encoding_layers,
            prev_encodings=prev_encodings)
        if substr_results:
            return substr_results[0]

        # Check if direct hash or plaintext
        rv = self.check_if_in_precompute_pool(string)
        # print('result', rv)
        if rv is not None:
            return prev_encodings + rv
        tokens = set()
        parameters = set()
        # don't split on the first layer
        if layers == self._hash_layers:
            tokens = set([string])
        else:
            try:
                self._split_on_delims(string, tokens, parameters)
            except Exception:
                tokens = set([string])
        tokens_union_params = tokens.union(parameters)
        for item in tokens_union_params:
            if len(item) == 2:
                value = item[1]
            else:
                value = item
            # Try encodings
            for encoding in self._encoding_set:
                # multiple rots are unnecessary
                if encoding.startswith('rot') and prev.startswith('rot'):
                    continue
                try:
                    # decoded = self._decoder.decode(encoding, string)
                    decoded = self._decoder.decode(encoding, value)
                    if type(decoded) == int:
                        decoded = str(decoded)

                except DecodeException:  # incorrect decoding
                    continue
                if decoded == string:  # don't add no-ops
                    continue
                if decoded is None:  # Empty decodings aren't useful
                    continue

                encoding_stack = prev_encodings + (encoding,)

                if layers > 1:
                    rv = self.check_for_leak(
                        decoded, layers-1, encoding_stack, encoding)
                    if rv is not None:
                        return rv
                else:
                    rv = self.check_if_in_precompute_pool(decoded)
                    if rv is not None:
                        return encoding_stack + rv
        return

    def _check_parts_for_leaks(self, tokens, parameters, nlayers):
        # print('_check_parts_for_leaks', tokens, parameters)
        """Check token and parameter string parts for leaks"""
        leaks = list()

        for token in tokens:
            # print('token', token)
            leak = self.check_for_leak(token, layers=nlayers)
            if leak is not None:
                leaks.append(leak)
        for name, value in parameters:
            prev_encodings = tuple()
            n_layers_param = nlayers
            # these URL params already decoded by parse_qs
            # decrement n_layers, and add to the the encoding stack
            if type(value) is tuple and name == 'parse_qs' and len(value) == 2:
                name = value[0]
                value = value[1]
                prev_encodings = ('urlencode',)
                n_layers_param = nlayers - 1

            leak = self.check_for_leak(
                value, layers=n_layers_param,
                prev_encodings=prev_encodings)
            if leak is not None:
                leaks.append(leak)
            leak = self.check_for_leak(
                name, layers=n_layers_param,
                prev_encodings=prev_encodings)
            if leak is not None:
                leaks.append(leak)

        return leaks

    def _split_url(self, url):
        """Split url path and query string on delimiters"""
        tokens = set()
        parameters = set()
        try:
            purl = urlparse(url)
        except ValueError:
            print("Can't parse url:", url)
            return [], []
        path_parts = purl.path.split('/')
        for part in path_parts:
            # TODO: consider removing this arbitrary exception for .com
            if "." in part and not part.endswith('.com'):
                part = re.sub(EXTENSION_RE, '', part)
            self._split_on_delims(part, tokens, parameters)
        self._split_on_delims(purl.query, tokens, parameters)
        # parse URL parameters
        for key, values in parse_qs(purl.query).items():
            for value in values:
                parameters.add(('parse_qs', (key, value)))

        self._split_on_delims(purl.fragment, tokens, parameters)
        return tokens, parameters

    def check_url(self, url, encoding_layers=3, substring_search=True):
        """Check if a given url contains a leak"""
        tokens, parameters = self._split_url(url)
        self._checked = defaultdict(set)  # reset the alreadt seen
        if self._debugging:
            print("URL tokens:")
            for token in tokens:
                print(token)
            print("\nURL parameters:")
            for key, value in parameters:
                print("Key: %s | Value: %s" % (key, value))
        path = get_path_from_url(url)
        return self._check_whole_and_parts_for_leaks(
            path, tokens, parameters, encoding_layers, substring_search)

    def _get_header_str(self, header_str, header_name):
        """Returns the header string parsed from `header_str`"""
        for item in json.loads(header_str):
            if item[0] == header_name:
                return item[1]
        return ""

    def _split_cookie(self, cookie_str):
        """Returns all parsed parts of the cookie names and values"""
        tokens = set()
        parameters = set()
        try:
            cookies = ck.SimpleCookie()
            cookies.load(cookie_str)
        except ck.CookieError:
            return tokens, parameters  # return empty sets

        for cookie in cookies.values():
            self._split_on_delims(cookie.key, tokens, parameters)
            self._split_on_delims(cookie.value, tokens, parameters)
        return tokens, parameters

    def get_location_str(self, header_str):
        return self._get_header_str(header_str, "Location")

    def get_referrer_str(self, header_str):
        return self._get_header_str(header_str, "Referer")

    def get_cookie_str(self, header_str, from_request=True):
        if not header_str:
            return ""
        if from_request:
            header_name = 'Cookie'
        else:
            header_name = 'Set-Cookie'

        return self._get_header_str(header_str, header_name)

    def check_cookies(self, header_str, encoding_layers=3,
                      from_request=True, substring_search=True):
        """Check the cookies portion of the header string for leaks"""
        cookie_str = self.get_cookie_str(header_str, from_request)
        if not cookie_str:
            return list()
        tokens, parameters = self._split_cookie(header_str, from_request=from_request)
        self._checked = defaultdict(set)
        return self._check_whole_and_parts_for_leaks(
            cookie_str, tokens, parameters, encoding_layers, substring_search)

    def check_cookie_str(self, cookie_str, encoding_layers=3, substring_search=True):
        """Check the cookie (either request or response) string for leaks"""
        if not cookie_str:
            return list()
        tokens, parameters = self._split_cookie(cookie_str)
        self._checked = defaultdict(set)
        return self._check_whole_and_parts_for_leaks(
            cookie_str, tokens, parameters, encoding_layers, substring_search)

    def check_location_header(self, location_str, encoding_layers=3,
                              substring_search=True):
        """Check the Location HTTP response header for leaks."""
        if location_str == '':
            return list()
        tokens, parameters = self._split_url(location_str)
        self._checked = defaultdict(set)
        return self._check_whole_and_parts_for_leaks(
            location_str, tokens, parameters, encoding_layers,
            substring_search)

    def check_post_data(self, post_str, encoding_layers=3,
                        substring_search=True):
        """Check the Location HTTP response header for leaks."""
        if post_str == '':
            return list()
        tokens, parameters = self._split_url(post_str)
        self._checked = defaultdict(set)
        self._split_on_delims(post_str, tokens, parameters)
        # tokens, parameters = self._split_cookie(post_str, from_request=False)
        return self._check_whole_and_parts_for_leaks(
            post_str, tokens, parameters, encoding_layers, substring_search)

    def check_referrer_header(self, header_str, encoding_layers=3,
                              substring_search=True):
        """Check the Referer HTTP request header for leaks."""
        if header_str == '':
            return list()
        referrer_str = self.get_referrer_str(header_str)
        if not referrer_str:
            return list()
        tokens, parameters = self._split_url(referrer_str)
        self._checked = defaultdict(set)
        return self._check_whole_and_parts_for_leaks(
            referrer_str, tokens, parameters, encoding_layers,
            substring_search)

    def check_referrer_str(self, referrer_str, encoding_layers=3,
                           substring_search=True):
        """Check the Referer HTTP request header for leaks."""
        if not referrer_str:
            return list()
        tokens, parameters = self._split_url(referrer_str)
        self._checked = defaultdict(set)
        return self._check_whole_and_parts_for_leaks(
            referrer_str, tokens, parameters, encoding_layers,
            substring_search)

    def _check_whole_and_parts_for_leaks(self, input_string, tokens,
                                         parameters, encoding_layers,
                                         substring_search):
        """Search an input string and its parts for leaks."""
        # print('_check_whole_and_parts_for_leaks', input_string, tokens, parameters)
        results = self._check_parts_for_leaks(tokens, parameters,
                                              encoding_layers)
        if substring_search:
            # print('input_string', input_string)
            substr_results = self.substring_search(input_string, max_layers=2)
            # filter repeating results
            return list(set(results + substr_results))
        else:
            return results

    def substring_search(self, input_string, max_layers=None, prev_encodings=tuple()):
        """Do a substring search for all precomputed hashes/encodings
        `max_layers` limits the number of encoding/hashing layers used in the
        substring search (to limit time). The default is no limit (`None`).
        """
        if input_string is None or input_string == '':
            return list()
        if not isinstance(input_string, bytes):
            try:
                input_string = input_string.encode('utf8')
            except (UnicodeDecodeError, UnicodeEncodeError):
                return list()

        leaks = list()
        n_prev_encodings = len(prev_encodings)
        # max - 1
        n_max_precomp_layer = max_layers - n_prev_encodings

        for n_precomp_layer in range(1, n_max_precomp_layer + 1):
            _precompute_pool = self._precompute_pool_by_layer[n_precomp_layer]
            for transform_stack, string in _precompute_pool.items():
                if string in input_string:
                    leaks.append(prev_encodings + transform_stack)
        return leaks


def detect_for_debug():
    PWD = 'mypwd111111111111'
    EMAIL = 'cosicadam0+cision.com@gmail.com'
    EMAIL2 = '11111@gmail.com'

    leak_detector = LeakDetector(
            [PWD, EMAIL, EMAIL2], encoding_set=ENCODINGS_NO_ROT,
            hash_set=LIKELY_HASHES,
            encoding_layers=3,
            hash_layers=3,
            debugging=False
        )
    # mmh2_32 false positive
    # SHOULD_NOT_FIND_URL = "https://www.google.com/pagead/1p-user-list/962065077/?random=1622325325876&cv=9&fst=1622322000000&num=1&bg=ffffff&guid=ON&eid=2505059651&u_h=600&u_w=800&u_ah=600&u_aw=800&u_cd=24&u_his=3&u_tz=0&u_java=false&u_nplug=0&u_nmime=0&gtm=2oa5q1&sendb=1&data=event%3Dgtag.config&frm=0&url=https%3A%2F%2Fwebapp.wisestamp.com%2Flogin%3F_gl%3D1*ecbcmc*_ga*MTk4MzEzMzQyOS4xNjIyMzI1MzEz*_ga_PEMJHV10HE*MTYyMjMyNTMxMy4xLjAuMTYyMjMyNTMxMy4w%26_ga%3D2.16593790.911772428.1622325313-1983133429.1622325313&ref=https%3A%2F%2Fwww.wisestamp.com%2F&tiba=WiseStamp%20Login&async=1&fmt=3&is_vtc=1&random=2723650945&resp=GooglemKTybQhCsO&rmt_tld=0&ipr=y"

    post_leaks = ""
    # URL = "https://track.securedvisit.com/citecapture/?cc_event=login&cc_context=Email%20Capture&sv_cid=0051_00591&sv_onetag_id=3495&sv_session=3e283c2e928dab75afa20d5952822551&sv_ver=1.8.4&sv_dt=2021-06-01T07%3A41%3A21.715Z&sv_referrer=&sv_url=https%3A%2F%2Fwww.thecompanystore.com%2F&sv_title=We%27re%20All%20About%20Comfort%20%7C%20The%20Company%20Store&sv_keywords=null&cc_data=%7B%22gK_gg_ikD1q%22%3A%22gzv1gDKDkp%2BNYigzk3DWHvNzli.gzk%40FkD1q.gzk%22%7D"
    # URL = "https://p.alocdn.com/c/2973/m/43b08b800bea7e3cf9c36c51d0c9f397/i/1062/s/3c547db27cf9dd35ea33a126ce6d61b4fc2a2274/is/1062/t/857b803d0c057d5a008e6be6102b0c5f3f9683f2e3839a18ebd1890598adf2bf/it/1062/p.gif"
    URL = "https://www.awin1.com/a/b.php?merchantId=6604&hash=efd356ba6de9ca3f73f09823bff72f5dc8bdc026324c00350a94d4431963e96c&bId=HLEX_60d441ba361b17.54766982"

    # POST_DATA = "eyJldmVudCI6ICJpZGVudGlmeSIsInByb3BlcnRpZXMiOiB7Im9zIjogIkxpbnV4IiwiYnJvd3NlciI6ICJDaHJvbWUiLCJkZXZpY2UiOiAiT3RoZXIiLCJtcF9saWIiOiAid2ViIiwiZGlzdGluY3RfaWQiOiAiMTdhMWY3YTgwYzIxNjgtMGFmZDE4OTg2ODdlMzktM2M3MTBlNTgtMWZhNDAwLTE3YTFmN2E4MGMzMTNlIiwiY3VzdG9tZXIiOiB7ImVtYWlsIjogIk1URkFaMjFoYVd3dVkyOXQiLCJzb3VyY2UiOiAiY3VzdG9tIiwic291cmNlX2RldGFpbCI6ICJzaG9waWZ5X0N1c3RvbWVyRW1haWwifSwidXJsIjogImh0dHBzOi8vd3d3LnZvbGNvbS5jb20vYWNjb3VudC9sb2dpbiIsImludGVncmF0aW9uX3ZlcnNpb24iOiAxNjIxNDU3MTQ2LCJ0b2tlbiI6ICJ2b2xjb20iLCJldmVudF9zb3VyY2UiOiAibWFnZW50byJ9fQ=="
    for __ in range(1):
        # post_leaks = leak_detector.check_post_data(POST_DATA, encoding_layers=3)
        url_leaks = leak_detector.check_url(URL, encoding_layers=3)
    if len(post_leaks) or len(url_leaks):
        print(post_leaks, url_leaks)
    else:
        print("CANNOT FIND ANY LEAKS")


PROFILE = False

if __name__ == '__main__':
    # For debugging only
    if PROFILE:
        cProfile.runctx('detect_for_debug()', globals(), locals(), sort='time')
    else:
        detect_for_debug()
