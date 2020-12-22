import random, strutils, sequtils, sugar

import "../src/nauthy"

proc testIntToBytes() =
    randomize()
    for i in 1..20:
        let x: uint64 = rand(uint64)
        let bytes = intToBytes(x)
        doAssert bytes.len == 8, "common.intToBytes() returns byte sequence of incorrect length"
        var num = 0'u64
        for j in 1..bytes.len:
            let b = bytes[^j]
            num = num or ((uint64)(b) shl (8*(j-1)))
        doAssert num == x, "common.intToBytes() returns incorrect sequence $1 for number $2" % [$bytes, $x]

proc testBytesToInt() =
    randomize()
    var bytes: array[8, uint8]
    var x = 0'u64
    for i in 1..8:
        let b = rand(uint8)
        bytes[^i] = b
        x = x or ((uint64)(b) shl (8*(i-1)))
    let r = bytesToInt(bytes)
    doAssert x == r, "common.bytesToint() returns incorrect integer $1 for the byte sequence $2" % [$r, $bytes]

proc testBase32Decode() =
    var str = "The quick brown fox jumps over the lazy dog.".map(c => (byte)(c)).toSeq
    var encoded = "KRUGKIDROVUWG2ZAMJZG653OEBTG66BANJ2W24DTEBXXMZLSEB2GQZJANRQXU6JAMRXWOLQ="
    var decoded = base32Decode(encoded)
    doAssert decoded == str, "Test for common.base32Decode() failed; acutal=$1, output=$2" % [$str, $decoded]

    str = @[(byte)('a')]
    encoded = "ME======"
    decoded = base32Decode(encoded)
    doAssert decoded == str, "Test for common.base32Decode() failed; acutal=$1, output=$2" % [$str, $decoded]

    str = "ab".map(c => (byte)(c)).toSeq
    encoded = "MFRA===="
    decoded = base32Decode(encoded)
    doAssert decoded == str, "Test for common.base32Decode() failed; acutal=$1, output=$2" % [$str, $decoded]

    str = "abc".map(c => (byte)(c)).toSeq
    encoded = "MFRGG==="
    decoded = base32Decode(encoded)
    doAssert decoded == str, "Test for common.base32Decode() failed; acutal=$1, output=$2" % [$str, $decoded]

    str = "abcd".map(c => (byte)(c)).toSeq
    encoded = "MFRGGZA="
    decoded = base32Decode(encoded)
    doAssert decoded == str, "Test for common.base32Decode() failed; acutal=$1, output=$2" % [$str, $decoded]

    str = "abcde".map(c => (byte)(c)).toSeq
    encoded = "MFRGGZDF"
    decoded = base32Decode(encoded)
    doAssert decoded == str, "Test for common.base32Decode() failed; acutal=$1, output=$2" % [$str, $decoded]

proc testBase32Encode() =
    var str = "The quick brown fox jumps over the lazy dog."
    var correctEncoding = "KRUGKIDROVUWG2ZAMJZG653OEBTG66BANJ2W24DTEBXXMZLSEB2GQZJANRQXU6JAMRXWOLQ="
    var encoded = base32Encode(str)
    doAssert encoded == correctEncoding, "Test for common.testBase32Encode() failed; correctEncoding = $1 but base32Encode() gives $2" % [$correctEncoding, $encoded]

    str = "a"
    correctEncoding = "ME======"
    encoded = base32Encode(str)
    doAssert encoded == correctEncoding, "Test for common.testBase32Encode() failed; correctEncoding = $1 but base32Encode() gives $2" % [$correctEncoding, $encoded]

    str = "ab"
    correctEncoding = "MFRA===="
    encoded = base32Encode(str)
    doAssert encoded == correctEncoding, "Test for common.testBase32Encode() failed; correctEncoding = $1 but base32Encode() gives $2" % [$correctEncoding, $encoded]

    str = "abc"
    correctEncoding = "MFRGG==="
    encoded = base32Encode(str)
    doAssert encoded == correctEncoding, "Test for common.testBase32Encode() failed; correctEncoding = $1 but base32Encode() gives $2" % [$correctEncoding, $encoded]

    str = "abcd"
    correctEncoding = "MFRGGZA="
    encoded = base32Encode(str)
    doAssert encoded == correctEncoding, "Test for common.testBase32Encode() failed; correctEncoding = $1 but base32Encode() gives $2" % [$correctEncoding, $encoded]

    str = "abcde"
    correctEncoding = "MFRGGZDF"
    encoded = base32Encode(str)
    doAssert encoded == correctEncoding, "Test for common.testBase32Encode() failed; correctEncoding = $1 but base32Encode() gives $2" % [$correctEncoding, $encoded]

testIntToBytes()
testBytesToInt()
testBase32Decode()
testBase32Encode()