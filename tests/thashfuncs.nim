import strutils, sequtils, sugar
include "nauthy/hashfuncs"

proc testHmacSha1() =
    var k: Bytes = "key".map(c => (byte)(c))
    var msg: Bytes = "The quick brown fox jumps over the lazy dog".map(c => (byte)(c))
    let correctOutput = @[222'u8, 124, 155, 133, 184, 183, 138, 166, 188, 138, 122, 54, 247, 10, 144, 112, 28, 157, 180, 217]
    var result = hmacX(k, msg, sha1Hash)
    doAssert result == correctOutput, "Test for HMAC_SHA1 failed: correct value = $1, result = $2" % [$correctOutput, $result]

    k = "12345678901234567890".map(c => (byte)(c))
    let correctResults = [
        [204'u8, 147, 207, 24, 80, 141, 148, 147, 76, 100, 182, 93, 139, 167, 102, 127, 183, 205, 228, 176],
        [117'u8, 164, 138, 25, 212, 203, 225, 0, 100, 78, 138, 193, 57, 126, 234, 116, 122, 45, 51, 171],
        [11'u8, 172, 183, 250, 8, 47, 239, 48, 120, 34, 17, 147, 139, 193, 197, 231, 4, 22, 255, 68],
        [102'u8, 194, 130, 39, 208, 58, 45, 85, 41, 38, 47, 240, 22, 161, 230, 239, 118, 85, 126, 206],
        [169'u8, 4, 201, 0, 166, 75, 53, 144, 152, 116, 179, 62, 97, 197, 147, 138, 142, 21, 237, 28],
        [163'u8, 126, 120, 61, 123, 114, 51, 192, 131, 212, 246, 41, 38, 199, 162, 95, 35, 141, 3, 22],
        [188'u8, 156, 210, 133, 97, 4, 44, 131, 242, 25, 50, 77, 60, 96, 114, 86, 192, 50, 114, 174],
        [164'u8, 251, 150, 12, 11, 192, 110, 30, 171, 184, 4, 229, 179, 151, 205, 196, 180, 85, 150, 250],
        [27'u8, 60, 137, 246, 94, 108, 158, 136, 48, 18, 5, 40, 35, 68, 63, 4, 139, 67, 50, 219],
        [22'u8, 55, 64, 152, 9, 166, 121, 220, 105, 130, 7, 49, 12, 140, 127, 192, 114, 144, 217, 229]
    ]
    for i in 0..9:
        let c = intToBytes((uint64)(i))
        let result = hmacX(k, c, sha1Hash)
        let correct = correctResults[i]
        doAssert result == correct, "Test for HMAC_SHA1 failed: correct value = $1, result = $2" % [$correctOutput, $result]

proc testHmacMD5() =
    let k: Bytes = "key".map(c => (byte)(c))
    let msg: Bytes = "The quick brown fox jumps over the lazy dog".map(c => (byte)(c))
    let correctOutput = @[128'u8, 7, 7, 19, 70, 62, 119, 73, 185, 12, 45, 194, 73, 17, 226, 117]
    doAssert hmacX(k, msg, md5Hash) == correctOutput, "Test for HMAC_MD5 failed"

testHmacSha1()
testHmacMD5()