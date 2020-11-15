import endians
import std/sha1
import typetraits
import sequtils
import math
import strutils
import times

type
    Bytes = seq[byte]

proc intToBytes(num: uint64): Bytes =
    ## Convert `num` to a sequence of 8 bytes in big endian.
    result = newSeq[byte](8)
    var cp = @[num]
    bigEndian64(result[0].addr, cp[0].addr)

proc bytesToint(numb: Bytes): uint64 =
    ## Convert the sequence of bytes `numb` in big endian to integer.
    for i in 1..numb.len:
        result += uint64(numb[^i]) * uint64(256^(i-1))

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

proc hotp(key: Bytes, counter: uint64, digits = 6): string =
    ## Generates HOTP value from `key` and `counter`.
    let c: Bytes = intToBytes(counter)
    let mac: Bytes = hmacSha1(key, c)
    let i: int = int(mac[^1]) mod 16
    var truncated: uint64 = bytesToint(mac[i..i+3]) mod uint64(2^31)
    truncated = truncated mod uint64(10 ^ 6)
    result = align($truncated, digits, '0')

proc totp(key: Bytes, digits = 6, tk: int64 = 30, t0: int64 = 0): string =
    ## Generates TOTP value from `key` using `t0` as the initial point in time
    ## to start counting the time steps and the duration of each time step is
    ## `tk` seconds. `t0` is Unix epoch so it is set to 0 by default.
    let c = (int64(epochTime()) - t0) div tk
    result = hotp(key, c.uint64)

var key: Bytes = @[byte(8), 36, 77, 234, 68, 20, 73, 61, 235, 122]
echo hotp(key, 2)

echo totp(@[byte(72), 101, 108, 108, 111, 33, 222, 173, 190, 239])