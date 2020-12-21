import sugar
import sequtils
import ./common
import std/sha1
import typetraits
import md5
import strutils

proc hmacX*(key: Bytes, message: Bytes, hash: HashFunc, blockSize: int): Bytes =
    ## Generic HMAC implementation. Specify a hash function as argument to implement
    ## specific HMAC such as HMAC_SHA256 and HMAC_MD5.
    const opadValue = byte(0x5c)
    const ipadValue = byte(0x36)

    var key = key
    if key.len > blockSize:
        key = hash(key)
    if key.len < blockSize:
        key = key & newSeq[byte](blockSize - key.len)
    
    let oKeyPad = map(key, proc(x: byte): byte = x xor opadValue)
    let iKeyPad = map(key, proc(x: byte): byte = x xor ipadValue)

    result = hash(oKeyPad & hash(iKeyPad & message))

proc sha1Hash(input: Bytes): Bytes =
    ## Generates SHA-1 hash from `input`.
    var str: string = ""
    for b in input:
        str.add(chr(b))
    result = @(distinctBase(secureHash(str)))

proc hmacSha1*(key, message : openArray[byte] | string): Bytes =
    let key = key.map(c => (byte)(c)).toSeq
    let message = message.map(c => (byte)(c)).toSeq
    result = hmacX(key, message, sha1Hash, 64)

proc md5hash(input: Bytes): Bytes =
    var str: string
    for c in input:
        str.add(chr(c))
    str = getMD5(str)
    result = cast[Bytes](parseHexStr(str))

proc hmacMD5*(key, message : openArray[byte] | string): Bytes =
    let key = key.map(c => (byte)(c)).toSeq
    let message = message.map(c => (byte)(c)).toSeq
    result = hmacX(key, message, md5hash, 64)