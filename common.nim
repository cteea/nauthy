import endians
import strutils
import math
import sequtils
import sugar

const b32Table* = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                   'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                   'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                   'Y', 'Z', '2', '3', '4', '5', '6', '7']

type
    Bytes* = seq[byte]
    HashFunc* = proc (data: Bytes): Bytes

proc intToBytes*(num: uint64): Bytes =
    ## Convert `num` to a sequence of 8 bytes in big endian.
    result = newSeq[byte](8)
    var cp = @[num]
    bigEndian64(result[0].addr, cp[0].addr)

proc bytesToInt*(numb: openArray[byte]): uint64 =
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

proc base32Encode*(input: openArray[byte | char]): string =
    ## Encode the `input` into Base-32
    var padding: string
    if input.len mod 5 == 1:
        padding = repeat('=', 6)
    elif input.len mod 5 == 2:
        padding = repeat('=', 4)
    elif input.len mod 5 == 3:
        padding = repeat('=', 3)
    elif input.len mod 5 == 4:
        padding = "="
    var input = input.map(c => (byte)(c)).toSeq
    if input.len mod 5 != 0:
        input = input & newSeq[byte](5 - (input.len mod 5))
    for i in countup(0, input.len-1, 5):
        let blk = input[i..i+4]
        var x = 0'u64
        for j in 0..4:
            x = x or ((uint64)(blk[j]) shl ((4-j)*8))
        echo "x = ", x
        var m = 0xf800000000'u64
        for j in 0..7:
            let c = (x and m) shr ((7 - j)*5)
            echo c
            result.add(b32Table[c])
            m = m shr 5
    
    if padding.len != 0:
        result[^padding.len .. ^1] = padding

proc base32Encode*(input: string): string =
    ## Encode the `input` into Base-32
    let input = input.map(c => (char)(c)).toSeq
    result = base32Encode(input)