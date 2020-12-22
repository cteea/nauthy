import sequtils
import ./common
import std/sha1
import typetraits
import md5
import strutils

proc hmacX*(key: Bytes, message: Bytes, hash: HashFunc): Bytes =
    ## Generic HMAC implementation. Specify a hash function as argument to implement
    ## specific HMAC such as HMAC_SHA256 and HMAC_MD5.
    const opadValue = byte(0x5c)
    const ipadValue = byte(0x36)

    var key = key
    if key.len > hash.blockSize:
        key = hash.hash(key)
    if key.len < hash.blockSize:
        key = key & newSeq[byte](hash.blockSize - key.len)
    
    let oKeyPad = map(key, proc(x: byte): byte = x xor opadValue)
    let iKeyPad = map(key, proc(x: byte): byte = x xor ipadValue)

    result = hash.hash(oKeyPad & hash.hash(iKeyPad & message))

proc sha1Digest*(input: Bytes): Bytes =
    ## Generates SHA-1 hash from `input`.
    var str: string = ""
    for b in input:
        str.add(chr(b))
    result = @(distinctBase(secureHash(str)))

let sha1Hash*: HashFunc = (hash: sha1Digest, blockSize: 64)

# proc hmacSha1*(key, message : Bytes): Bytes =
#     let key = key.map(c => (byte)(c))
#     let message = message.map(c => (byte)(c))
#     result = hmacX(key, message, sha1Hash, 64)

proc md5Digest*(input: Bytes): Bytes =
    var str: string
    for c in input:
        str.add(chr(c))
    str = getMD5(str)
    result = cast[Bytes](parseHexStr(str))

let md5Hash*: HashFunc = (md5Digest, 64)

# proc hmacMD5*(key, message : Bytes): Bytes =
#     let key = key.map(c => (byte)(c)).toSeq
#     let message = message.map(c => (byte)(c)).toSeq
#     result = hmacX(key, message, md5hash, 64)
