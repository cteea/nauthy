import "../hmac"

proc testHmacSha1() =
    let k = "key"
    let msg = "The quick brown fox jumps over the lazy dog"
    let correctOutput = @[222'u8, 124, 155, 133, 184, 183, 138, 166, 188, 138, 122, 54, 247, 10, 144, 112, 28, 157, 180, 217]
    doAssert hmacSha1(k, msg) == correctOutput, "Test for hamcSha1 failed"

proc testHmacMD5() =
    let k = "key"
    let msg = "The quick brown fox jumps over the lazy dog"
    let correctOutput = @[128'u8, 7, 7, 19, 70, 62, 119, 73, 185, 12, 45, 194, 73, 17, 226, 117]
    doAssert hmacMD5(k, msg) == correctOutput, "Test for hamcSha1 failed"

testHmacSha1()
testHmacMD5()