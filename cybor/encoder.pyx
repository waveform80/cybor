import re
import math
import struct
from collections import OrderedDict, defaultdict
from contextlib import contextmanager
from functools import wraps
from datetime import datetime, date, time, timezone
from io import BytesIO

from .types import CBORTag, undefined, CBORSimpleValue, FrozenDict


class CBOREncodeError(ValueError):
    """
    Raised when an error occurs while serializing an object into a CBOR
    datastream.
    """


def shareable_encoder(func):
    """
    Decorator wrapping an encoder method to handle cyclic data structures (or
    general scalar value sharing).

    If value sharing is enabled, this marks the given value shared in the
    output stream on the first call. If the value has already been passed to
    this method, a reference marker is instead written to the data stream and
    the wrapped method is not called.

    If value sharing is disabled, only infinite recursion protection is done.
    """
    @wraps(func)
    def wrapper(encoder, value):
        encoder.encode_shared(func, value)
    return wrapper


cdef class CBOREncoder:
    """
    Serializes objects to a byte stream using Concise Binary Object
    Representation.

    :param bool datetime_as_timestamp:
        set to ``True`` to serialize datetimes as UNIX timestamps (this makes
        datetimes more concise on the wire but loses the time zone information)
    :param datetime.tzinfo timezone:
        the default timezone to use for serializing naive datetimes
    :param bool value_sharing:
        if ``True``, allows more efficient serializing of repeated values and,
        more importantly, cyclic data structures, at the cost of extra line
        overhead
    :param default:
        a callable that is called by the encoder with three arguments (encoder,
        value, file object) when no suitable encoder has been found, and should
        use the methods on the encoder to encode any objects it wants to add to
        the data stream
    :param bool canonical:
        Forces mapping types to be output in a stable order to guarantee that
        the output will always produce the same hash given the same input.
    """
    cdef object _write
    cdef object _encoders
    cdef dict _shared
    cdef object _timezone
    cdef bint _datetime_as_timestamp
    cdef bint _value_sharing
    cdef object _default_handler

    def __cinit__(self, fp, datetime_as_timestamp=False, timezone=None,
                 value_sharing=False, default=None, canonical=False):
        self.fp = fp
        self._shared = {}  # indexes used for value sharing
        self._encoders = default_encoders.copy()
        self._value_sharing = value_sharing
        self._datetime_as_timestamp = datetime_as_timestamp
        self._timezone = timezone
        self._default_handler = default
        if canonical:
            self._encoders.update(canonical_encoders)

    cdef object _find_encoder(self, object obj_type):
        from sys import modules

        for type_, enc in list(self._encoders.items()):
            if type(type_) is tuple:
                modname, typename = type_
                imported_type = getattr(modules.get(modname), typename, None)
                if imported_type is not None:
                    del self._encoders[type_]
                    self._encoders[imported_type] = enc
                    type_ = imported_type
                else:  # pragma: nocover
                    continue

            if issubclass(obj_type, type_):
                self._encoders[obj_type] = enc
                return enc

    #
    # Property accessors
    #

    @property
    def datetime_as_timestamp(self):
        return self._datetime_as_timestamp

    @datetime_as_timestamp.setter
    def datetime_as_timestamp(self, value):
        self._datetime_as_timestamp = bool(value)

    @property
    def value_sharing(self):
        return self._value_sharing

    @value_sharing.setter
    def value_sharing(self, value):
        self._value_sharing = bool(value)

    @property
    def timezone(self):
        return self._timezone

    @timezone.setter
    def timezone(self, value):
        self._timezone = value

    @property
    def fp(self):
        return self._write.__self__

    @fp.setter
    def fp(self, value):
        if callable(value.write):
            self._write = value.write
        else:
            raise ValueError('fp must have a callable write method')

    #
    # Utility I/O methods
    #

    def write(self, data):
        """
        Write bytes to the data stream.

        :param bytes data: the bytes to write
        """
        self._write(data)

    cdef void _encode_length(self, int major_tag, unsigned long long length):
        major_tag <<= 5
        if length < 24:
            self._write(struct.pack('>B', major_tag | length))
        elif length < 256:
            self._write(struct.pack('>BB', major_tag | 24, length))
        elif length < 65536:
            self._write(struct.pack('>BH', major_tag | 25, length))
        elif length < 4294967296:
            self._write(struct.pack('>BL', major_tag | 26, length))
        else:
            self._write(struct.pack('>BQ', major_tag | 27, length))

    def encode_length(self, major_tag, length):
        self._encode_length(major_tag, length)

    cdef int _encode_shared(self, object encoder, object value) except -1:
        cdef unsigned long long value_id
        cdef Py_ssize_t index

        value_id = id(value)
        try:
            index = self._shared[value_id][1]
        except KeyError:
            if self._value_sharing:
                self._shared[value_id] = (value, len(self._shared))
                self._encode_length(6, 28)
                encoder(self, value)
            else:
                self._shared[value_id] = (value, 0)
                try:
                    encoder(self, value)
                finally:
                    del self._shared[value_id]
        else:
            if self._value_sharing:
                self._encode_length(6, 29)
                self._encode_int(index)
            else:
                raise CBOREncodeError("cyclic data structure detected but "
                                      "value_sharing is False") from None
        return 0

    def encode_shared(self, encoder, value):
        self._encode_shared(encoder, value)

    #
    # Major encoders
    #

    cdef _encode_int(self, value):
        # Big integers (2 ** 64 and over)
        if value >= 18446744073709551616 or value < -18446744073709551616:
            if value >= 0:
                semantic_type = 2
            else:
                semantic_type = 3
                value = -value - 1

            bits = value.bit_length()
            payload = value.to_bytes((bits + 7) // 8, 'big')
            self.encode_semantic(CBORTag(semantic_type, payload))
        elif value >= 0:
            self._encode_length(0, <unsigned long long>value)
        else:
            self._encode_length(1, <unsigned long long>-(value + 1))

    def encode_int(self, value):
        self._encode_int(value)

    def encode_bytestring(self, value):
        self._encode_length(2, len(value))
        self._write(value)

    def encode_bytearray(self, value):
        self.encode_bytestring(bytes(value))

    def encode_string(self, value):
        buf = value.encode('utf-8')
        self._encode_length(3, len(buf))
        self._write(buf)

    @shareable_encoder
    def encode_array(self, value):
        self._encode_length(4, len(value))
        for item in value:
            self.encode(item)

    cdef encode_dict(self, dict value):
        self._encode_length(5, len(value))
        for key, val in value.items():
            self.encode(key)
            self.encode(val)

    @shareable_encoder
    def encode_map(self, value):
        if type(value) == dict:
            self.encode_dict(<dict>value)
        else:
            self._encode_length(5, len(value))
            for key, val in value.items():
                self.encode(key)
                self.encode(val)

    def _encode_sortable_key(self, value):
        """
        Takes a key and calculates the length of its optimal byte
        representation.
        """
        encoded = self.encode_to_bytes(value)
        return len(encoded), encoded

    @shareable_encoder
    def encode_canonical_map(self, value):
        """Reorder keys according to Canonical CBOR specification"""
        keyed_list = (
            (self._encode_sortable_key(key), (key, value))
            for key, value in value.items()
        )
        self._encode_length(5, len(value))
        for (length, encoded), (key, value) in sorted(keyed_list):
            self._write(encoded)
            self.encode(value)

    def encode_semantic(self, value):
        self._encode_length(6, value.tag)
        self.encode(value.value)

    #
    # Semantic encoders (major tag 6)
    #

    def encode_datetime(self, value):
        # Semantic tag 0
        if not value.tzinfo:
            if self.timezone:
                value = value.replace(tzinfo=self.timezone)
            else:
                raise CBOREncodeError(
                    'naive datetime encountered and no default timezone has '
                    'been set')

        if self.datetime_as_timestamp:
            self.encode_semantic(
                CBORTag(1, value.timestamp()))
        else:
            self.encode_semantic(
                CBORTag(0, value.isoformat().replace('+00:00', 'Z')))

    def encode_date(self, value):
        value = datetime.combine(value, time()).replace(tzinfo=timezone.utc)
        self.encode_datetime(value)

    def encode_decimal(self, value):
        # Semantic tag 4
        if value.is_nan():
            self._write(b'\xf9\x7e\x00')
        elif value.is_infinite():
            self._write(b'\xf9\x7c\x00' if value > 0 else b'\xf9\xfc\x00')
        else:
            dt = value.as_tuple()
            sig = 0
            for digit in dt.digits:
                sig = (sig * 10) + digit
            if dt.sign:
                sig = -sig
            with self.disable_value_sharing():
                self.encode_semantic(CBORTag(4, [dt.exponent, sig]))

    def encode_rational(self, value):
        # Semantic tag 30
        with self.disable_value_sharing():
            self.encode_semantic(CBORTag(30, [value.numerator, value.denominator]))

    def encode_regexp(self, value):
        # Semantic tag 35
        self.encode_semantic(CBORTag(35, value.pattern))

    def encode_mime(self, value):
        # Semantic tag 36
        self.encode_semantic(CBORTag(36, value.as_string()))

    def encode_uuid(self, value):
        # Semantic tag 37
        self.encode_semantic(CBORTag(37, value.bytes))

    def encode_set(self, value):
        # Semantic tag 258
        self.encode_semantic(CBORTag(258, tuple(value)))

    def encode_canonical_set(self, value):
        # Semantic tag 258
        values = sorted(
            (self._encode_sortable_key(key), key)
            for key in value
        )
        self.encode_semantic(CBORTag(258, tuple(key[0][1] for key in values)))

    def encode_ipaddress(self, value):
        # Semantic tag 260
        self.encode_semantic(CBORTag(260, value.packed))

    #
    # Special encoders (major tag 7)
    #

    def encode_simple_value(self, value):
        if value.value < 20:
            self._write(struct.pack('>B', 0xe0 | value.value))
        else:
            self._write(struct.pack('>BB', 0xf8, value.value))

    def encode_float(self, value):
        # Handle special values efficiently
        if math.isnan(value):
            self._write(b'\xf9\x7e\x00')
        elif math.isinf(value):
            self._write(b'\xf9\x7c\x00' if value > 0 else b'\xf9\xfc\x00')
        else:
            self._write(struct.pack('>Bd', 0xfb, value))

    def encode_minimal_float(self, value):
        # Handle special values efficiently
        # TODO optimize with fast C half-float implementation
        self.encode_float(value)

    def encode_boolean(self, value):
        self._write(b'\xf5' if value else b'\xf4')

    def encode_none(self, value):
        self._write(b'\xf6')

    def encode_undefined(self, value):
        self._write(b'\xf7')

    @contextmanager
    def disable_value_sharing(self):
        """
        Disable value sharing in the encoder for the duration of the context
        block.
        """
        old_value_sharing = self.value_sharing
        self.value_sharing = False
        yield
        self.value_sharing = old_value_sharing

    cdef int _encode(self, object obj) except -1:
        """
        Encode the given object using CBOR.

        :param object obj: the object to encode
        """
        obj_type = obj.__class__
        encoder = (
            self._encoders.get(obj_type) or
            self._find_encoder(obj_type) or
            self.default_handler
        )
        if not encoder:
            raise CBOREncodeError('cannot serialize type %s' % obj_type.__name__)

        encoder(self, obj)
        return 0

    def encode(self, obj):
        self._encode(obj)

    def encode_to_bytes(self, obj):
        """
        Encode the given object to a byte buffer and return its value as bytes.

        This method was intended to be used from the ``default`` hook when an object needs to be
        encoded separately from the rest but while still taking advantage of the shared value
        registry.

        """
        old_fp = self.fp
        self.fp = fp = BytesIO()
        try:
            self.encode(obj)
        finally:
            self.fp = old_fp
        return fp.getvalue()


default_encoders = OrderedDict([
    (bytes,                         CBOREncoder.encode_bytestring),
    (bytearray,                     CBOREncoder.encode_bytearray),
    (unicode,                       CBOREncoder.encode_string),
    (int,                           CBOREncoder.encode_int),
    (float,                         CBOREncoder.encode_float),
    (('decimal', 'Decimal'),        CBOREncoder.encode_decimal),
    (bool,                          CBOREncoder.encode_boolean),
    (type(None),                    CBOREncoder.encode_none),
    (tuple,                         CBOREncoder.encode_array),
    (list,                          CBOREncoder.encode_array),
    (dict,                          CBOREncoder.encode_map),
    (defaultdict,                   CBOREncoder.encode_map),
    (OrderedDict,                   CBOREncoder.encode_map),
    (FrozenDict,                    CBOREncoder.encode_map),
    (type(undefined),               CBOREncoder.encode_undefined),
    (datetime,                      CBOREncoder.encode_datetime),
    (date,                          CBOREncoder.encode_date),
    (type(re.compile('')),          CBOREncoder.encode_regexp),
    (('fractions', 'Fraction'),     CBOREncoder.encode_rational),
    (('email.message', 'Message'),  CBOREncoder.encode_mime),
    (('uuid', 'UUID'),              CBOREncoder.encode_uuid),
    (('ipaddress', 'IPv4Address'),  CBOREncoder.encode_ipaddress),
    (('ipaddress', 'IPv6Address'),  CBOREncoder.encode_ipaddress),
    (CBORSimpleValue,               CBOREncoder.encode_simple_value),
    (CBORTag,                       CBOREncoder.encode_semantic),
    (set,                           CBOREncoder.encode_set),
    (frozenset,                     CBOREncoder.encode_set)
])

canonical_encoders = OrderedDict([
    (float,       CBOREncoder.encode_minimal_float),
    (dict,        CBOREncoder.encode_canonical_map),
    (defaultdict, CBOREncoder.encode_canonical_map),
    (OrderedDict, CBOREncoder.encode_canonical_map),
    (FrozenDict,  CBOREncoder.encode_canonical_map),
    (set,         CBOREncoder.encode_canonical_set),
    (frozenset,   CBOREncoder.encode_canonical_set)
])


def dumps(obj, **kwargs):
    """
    Serialize an object to a bytestring.

    :param object obj:
        the object to serialize
    :param kwargs:
        keyword arguments passed to :class:`CBOREncoder`
    :return: the serialized output
    :rtype: bytes
    """
    with BytesIO() as fp:
        dump(obj, fp, **kwargs)
        return fp.getvalue()


def dump(obj, fp, **kwargs):
    """
    Serialize an object to a file.

    :param object obj:
        the object to serialize
    :param fp:
        a file-like object
    :param kwargs:
        keyword arguments passed to :class:`CBOREncoder`
    """
    CBOREncoder(fp, **kwargs).encode(obj)
