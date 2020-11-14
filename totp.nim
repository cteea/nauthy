import endians
import std/sha1
import typetraits
import sequtils

type
    Bytes = seq[byte]

proc intToBytes(counter: uint64): Bytes =
    ## Convert `counter` to a sequence of 8 bytes.
    result = newSeq[byte](8)
    var cp = @[counter]
    bigEndian64(result[0].addr, cp[0].addr)

proc sha1Hash(input: Bytes): Bytes =
    ## Generates SHA-1 hash from `input`.
    var str: string = ""
    for b in input:
        str = str & char(b)
    result = @(distinctBase(secureHash(str)))

proc hmacSha1(key: Bytes, message: Bytes): Bytes =
    ## Generates HMAC hash from `key` and `message` using SHA-1 as the hashing
    ## function.
    const blockSize = 64
    const opadValue = byte(0x5c)
    const ipadValue = byte(0x36)

    var k: Bytes;
    if key.len > blockSize:
        k = sha1Hash(key)
    elif key.len < blockSize:
        k = key & newSeq[byte](blockSize - key.len)

    var oKeyPad = map(k, proc(x: byte): byte = x xor opadValue)
    var iKeyPad = map(k, proc(x: byte): byte = x xor ipadValue)

    result = sha1Hash(oKeyPad & sha1Hash(iKeyPad & message))

var key: Bytes = @[byte(8), 36, 77, 234, 68, 20, 73, 61, 235, 122]
var c: Bytes = intToBytes(1)
echo "key: ", key
echo "c: ", c
echo hmacSha1(key, c)