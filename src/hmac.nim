import sequtils, std/sha1, typetraits, md5, strutils
include "./utils"

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
    ## Generates SHA-1 hash from the given bytes.
    var str: string = ""
    for b in input:
        str.add(chr(b))
    result = @(distinctBase(secureHash(str)))

let sha1Hash*: HashFunc = (hash: sha1Digest, blockSize: 64)

proc md5Digest*(input: Bytes): Bytes =
    ## Generates MD5 hash from the given bytes.
    var str: string
    for c in input:
        str.add(chr(c))
    str = getMD5(str)
    result = cast[Bytes](parseHexStr(str))

let md5Hash*: HashFunc = (md5Digest, 64)
