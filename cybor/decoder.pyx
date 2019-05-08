import re
import struct
from datetime import datetime, timedelta, timezone
from io import BytesIO

from .types import CBORTag, undefined, break_marker, CBORSimpleValue, FrozenDict

timestamp_re = re.compile(r'^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)'
                          r'(?:\.(\d+))?(?:Z|([+-]\d\d):(\d\d))$')


class CBORDecodeError(ValueError):
    """
    Raised when an error occurs deserializing a CBOR datastream.
    """


class CBORDecoder():
    """
    Deserializes a CBOR encoded byte stream.

    :param tag_hook:
        Callable that takes 3 arguments: the decoder instance, the
        :class:`CBORTag` and the shareable index for the resulting object, if
        any. This callback is called for any tags for which there is no
        built-in decoder. The return value is substituted for the CBORTag
        object in the deserialized output.
    :param object_hook:
        Callable that takes 2 arguments: the decoder instance and the
        dictionary. This callback is called for each deserialized :class:`dict`
        object. The return value is substituted for the dict in the
        deserialized output.
    """

    __slots__ = ('fp', 'tag_hook', 'object_hook', '_shared_index',
                 '_shareables', '_immutable')

    def __init__(self, fp, tag_hook=None, object_hook=None):
        self.fp = fp
        self.tag_hook = tag_hook
        self.object_hook = object_hook
        self._share_index = None
        self._shareables = []
        self._immutable = False

    @property
    def immutable(self):
        """
        Used by decoders to check if the calling context requires an immutable
        type. Object_hook or tag_hook should raise an exception if this flag is
        set unless the result can be safely used as a dict key.
        """
        return self._immutable

    def _set_shareable(self, value):
        """
        Set the shareable value for the last encountered shared value marker,
        if any.

        :param object value:
            the shared value
        """
        if self._share_index is not None:
            self._shareables[self._share_index] = value

    def read(self, amount):
        """
        Read bytes from the data stream.

        :param int amount:
            the number of bytes to read
        """
        data = self.fp.read(amount)
        if len(data) < amount:
            raise CBORDecodeError(
                'premature end of stream (expected to read {} bytes, got {} '
                'instead)'.format(amount, len(data)))

        return data

    def decode_length(self, subtype, allow_indefinite=False):
        # Major tag 0
        if subtype < 24:
            return subtype
        elif subtype == 24:
            return struct.unpack('>B', self.read(1))[0]
        elif subtype == 25:
            return struct.unpack('>H', self.read(2))[0]
        elif subtype == 26:
            return struct.unpack('>L', self.read(4))[0]
        elif subtype == 27:
            return struct.unpack('>Q', self.read(8))[0]
        elif subtype == 31 and allow_indefinite:
            return None
        else:
            raise CBORDecodeError('unknown unsigned integer subtype 0x%x' % subtype)

    def decode_uint(self, subtype):
        # Major tag 0
        return self.decode_length(subtype)

    def decode_negint(self, subtype):
        # Major tag 1
        return -self.decode_length(subtype) - 1

    def decode_bytestring(self, subtype):
        # Major tag 2
        length = self.decode_length(subtype, allow_indefinite=True)
        if length is None:
            # Indefinite length
            buf = []
            while True:
                initial_byte = self.read(1)[0]
                if initial_byte == 0xff:
                    return b''.join(buf)
                else:
                    length = self.decode_uint(initial_byte & 31)
                    buf.append(self.read(length))
        else:
            return self.read(length)

    def decode_string(self, subtype):
        # Major tag 3
        return self.decode_bytestring(subtype).decode('utf-8')

    def decode_array(self, subtype):
        # Major tag 4
        items = []
        self._set_shareable(items)
        length = self.decode_length(subtype, allow_indefinite=True)
        if length is None:
            # Indefinite length
            while True:
                value = self.decode()
                if value is break_marker:
                    break
                else:
                    items.append(value)
        else:
            items = [None] * length
            for i in range(length):
                items[i] = self.decode()

        if self.immutable:
            items = tuple(items)
            self._set_shareable(items)
        return items

    def decode_map(self, subtype):
        # Major tag 5
        dictionary = {}
        self._set_shareable(dictionary)
        length = self.decode_length(subtype, allow_indefinite=True)
        if length is None:
            # Indefinite length
            while True:
                key = self._decode_immutable()
                if key is break_marker:
                    break
                else:
                    dictionary[key] = self.decode()
        else:
            for _ in range(length):
                key = self._decode_immutable()
                dictionary[key] = self.decode()

        if self.object_hook:
            dictionary = self.object_hook(self, dictionary)
            self._set_shareable(dictionary)
        elif self.immutable:
            dictionary = FrozenDict(dictionary)
            self._set_shareable(dictionary)
        return dictionary

    def decode_semantic(self, subtype):
        # Major tag 6
        tagnum = self.decode_length(subtype)
        semantic_decoder = semantic_decoders.get(tagnum)
        if semantic_decoder:
            return semantic_decoder(self)
        else:
            tag = CBORTag(tagnum, self.decode())
            if self.tag_hook:
                return self.tag_hook(tag)
            else:
                return tag

    def decode_special(self, subtype):
        # Simple value
        if subtype < 20:
            return CBORSimpleValue(subtype)
        # Major tag 7
        return special_decoders[subtype](self)


    #
    # Semantic decoders (major tag 6)
    #

    def decode_datetime_string(self):
        # Semantic tag 0
        value = self.decode()
        match = timestamp_re.match(value)
        if match:
            (
                year,
                month,
                day, hour,
                minute,
                second,
                micro,
                offset_h,
                offset_m,
            ) = match.groups()
            if offset_h:
                tz = timezone(timedelta(hours=int(offset_h),
                                        minutes=int(offset_m)))
            else:
                tz = timezone.utc

            return datetime(
                int(year), int(month), int(day),
                int(hour), int(minute), int(second), int(micro or 0), tz)
        else:
            raise CBORDecodeError('invalid datetime string: {}'.format(value))

    def decode_epoch_datetime(self):
        # Semantic tag 1
        value = self.decode()
        return datetime.fromtimestamp(value, timezone.utc)

    def decode_positive_bignum(self):
        # Semantic tag 2
        value = self.decode()
        return int.from_bytes(value, 'big')

    def decode_negative_bignum(self):
        # Semantic tag 3
        return -self.decode_positive_bignum() - 1

    def decode_fraction(self):
        # Semantic tag 4
        from decimal import Decimal
        exp, sig = self.decode()
        return sig * (10 ** exp)

    def decode_bigfloat(self):
        # Semantic tag 5
        from decimal import Decimal
        exp, sig = self.decode()
        return sig * (2 ** exp)

    def decode_shareable(self):
        # Semantic tag 28
        old_index = self._share_index
        self._share_index = len(self._shareables)
        self._shareables.append(None)
        try:
            return self.decode()
        finally:
            self._share_index = old_index

    def decode_sharedref(self):
        # Semantic tag 29
        value = self.decode()
        try:
            shared = self._shareables[value]
        except IndexError:
            raise CBORDecodeError('shared reference %d not found' % value)

        if shared is None:
            raise CBORDecodeError('shared value %d has not been initialized' % value)
        else:
            return shared

    def decode_rational(self):
        # Semantic tag 30
        from fractions import Fraction
        return Fraction(*self.decode())

    def decode_regexp(self):
        # Semantic tag 35
        return re.compile(self.decode())

    def decode_mime(self):
        # Semantic tag 36
        from email.parser import Parser
        return Parser().parsestr(self.decode())

    def decode_uuid(self):
        # Semantic tag 37
        from uuid import UUID
        return UUID(bytes=self.decode())

    def decode_set(self):
        # Semantic tag 258
        if self.immutable:
            return frozenset(self._decode_immutable())
        else:
            return set(self._decode_immutable())

    #
    # Special decoders (major tag 7)
    #

    def decode_simple_value(self):
        return CBORSimpleValue(self.read(1)[0])

    def decode_float16(self):
        # TODO re-write with C half-float implementation
        return struct.unpack('>f', self.read(4))[0]

    def decode_float32(self):
        return struct.unpack('>f', self.read(4))[0]

    def decode_float64(self):
        return struct.unpack('>d', self.read(8))[0]

    def decode(self):
        """
        Decode the next value from the stream.

        :raises CBORDecodeError: if there is any problem decoding the stream
        """
        initial_byte = self.fp.read(1)[0]
        major_type = initial_byte >> 5
        subtype = initial_byte & 31
        return major_decoders[major_type](self, subtype)

    def _decode_immutable(self):
        old_immutable = self.immutable
        self._immutable = True
        try:
            return self.decode()
        finally:
            self._immutable = old_immutable

    def decode_from_bytes(self, buf):
        """
        Wrap the given bytestring as a file and call :meth:`decode` with it as
        the argument.

        This method was intended to be used from the ``tag_hook`` hook when an
        object needs to be decoded separately from the rest but while still
        taking advantage of the shared value registry.
        """
        old_fp = self.fp
        self.fp = BytesIO(buf)
        try:
            retval = self.decode()
        finally:
            self.fp = old_fp
        return retval


major_decoders = {
    0: CBORDecoder.decode_uint,
    1: CBORDecoder.decode_negint,
    2: CBORDecoder.decode_bytestring,
    3: CBORDecoder.decode_string,
    4: CBORDecoder.decode_array,
    5: CBORDecoder.decode_map,
    6: CBORDecoder.decode_semantic,
    7: CBORDecoder.decode_special
}

special_decoders = {
    20: lambda self: False,
    21: lambda self: True,
    22: lambda self: None,
    23: lambda self: undefined,
    24: CBORDecoder.decode_simple_value,
    25: CBORDecoder.decode_float16,
    26: CBORDecoder.decode_float32,
    27: CBORDecoder.decode_float64,
    31: lambda self: break_marker
}

semantic_decoders = {
    0:   CBORDecoder.decode_datetime_string,
    1:   CBORDecoder.decode_epoch_datetime,
    2:   CBORDecoder.decode_positive_bignum,
    3:   CBORDecoder.decode_negative_bignum,
    4:   CBORDecoder.decode_fraction,
    5:   CBORDecoder.decode_bigfloat,
    29:  CBORDecoder.decode_sharedref,
    30:  CBORDecoder.decode_rational,
    35:  CBORDecoder.decode_regexp,
    36:  CBORDecoder.decode_mime,
    37:  CBORDecoder.decode_uuid,
    258: CBORDecoder.decode_set
}


def loads(payload, **kwargs):
    """
    Deserialize an object from a bytestring.

    :param bytes payload:
        the bytestring to serialize
    :param kwargs:
        keyword arguments passed to :class:`CBORDecoder`
    :return: the deserialized object
    """
    with BytesIO(payload) as fp:
        return CBORDecoder(fp, **kwargs).decode()


def load(fp, **kwargs):
    """
    Deserialize an object from an open file.

    :param fp:
        the input file (any file-like object)
    :param kwargs:
        keyword arguments passed to :class:`CBORDecoder`
    :return: the deserialized object
    """
    return CBORDecoder(fp, **kwargs).decode()
