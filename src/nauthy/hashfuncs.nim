import sequtils, std/sha1, typetraits, md5, strutils, tables, algorithm
import nimSHA2
include "./utils"

type
  Algorithm* = enum
    MD5,
    SHA1,
    SHA256,
    SHA512

proc hmacX(key: Bytes, message: Bytes, hash: HashFunc): Bytes {.used.} =
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

proc sha1Digest(input: Bytes): Bytes =
  ## Generates SHA-1 hash from the given bytes.
  let input = cast[string](input)
  result = @(distinctBase(secureHash(input)))

const sha1Hash*: HashFunc = (hash: sha1Digest, blockSize: 64, name: $SHA1)

proc md5Digest(input: Bytes): Bytes =
  ## Generates MD5 hash from the given bytes.
  let input = cast[string](input)
  let digest = getMD5(input)
  result = cast[Bytes](parseHexStr(digest))

const md5Hash*: HashFunc = (hash: md5Digest, blockSize: 64, name: $MD5)

proc sha256Digest(input: Bytes): Bytes =
  let input = cast[string](input)
  let digest = computeSHA256(input).toSeq()
  result = cast[Bytes](digest)

const sha256Hash*: HashFunc = (hash: sha256Digest, blockSize: 64, name: $SHA256)

proc sha512Digest(input: Bytes): Bytes =
  let input = cast[string](input)
  let digest = computeSHA512(input).toSeq()
  result = cast[Bytes](digest)

const sha512Hash*: HashFunc = (hash: sha512Digest, blockSize: 128, name: $SHA512)

func getAlgorithm*(name: auto): auto {.gcsafe.} =
  case name
  of MD5: result = md5Hash
  of SHA1: result = sha1Hash
  of SHA256: result = sha256Hash
  of SHA512: result = sha512Hash
