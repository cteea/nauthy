import endians
import strutils
import math

type
    Bytes* = seq[byte]
    HashFunc* = proc (data: Bytes): Bytes

proc intToBytes*(num: uint64): Bytes =
    ## Convert `num` to a sequence of 8 bytes in big endian.
    result = newSeq[byte](8)
    var cp = @[num]
    bigEndian64(result[0].addr, cp[0].addr)

proc bytesToint*(numb: Bytes): uint64 =
    ## Convert the sequence of bytes `numb` in big endian to integer.
    for i in 1..numb.len:
        result += uint64(numb[^i]) * uint64(256^(i-1))

proc b32AlphaDecode(c: char): uint64 =
    ## Convert Base-32 alphabet to corresponding value.
    ## NOTE: This proc assumes `c` is a valide RFC4648 Base-32 alphabet.
    if c == '=':
        result = 0
    elif c >= 'A' and c <= 'Z':
        result = uint64(ord(c) - ord('A'))
    else:
        result = 24 + parseBiggestUInt($c)

proc base32Decode*(str: string): Bytes =
    ## Decode the BASE32 encoded string `str` into sequence of bytes.
    let str = toUpperAscii(join(str.splitWhitespace))
    if (str.len * 5) mod 8 != 0:
        raise newException(CatchableError,
                "The given base32-encoded string has incomplete data block.")
    for i in countup(1, str.len, 8):
        var x: uint64 = 0
        for j in i .. i+7:
            let alpha = str[^j]
            if (alpha == '=' and j > i and str[^(j-1)] != '='):
                raise newException(CatchableError,
                    "Base32 string should only contain '=' as a padding at the end.")
            if (alpha notin {'A' .. 'Z', '2' .. '7', '='}):
                raise newException(CatchableError, "Base32 string contains invalid characters.")
            x = x or (b32AlphaDecode(alpha) shl ((j-i)*5)) 
        result = intToBytes(x)[3..7] & result
