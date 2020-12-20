import random, strutils

import "../common"

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
    let str = "The quick brown fox jumps over the lazy dog."
    let encoded = "KRUGKIDROVUWG2ZAMJZG653OEBTG66BANJ2W24DTEBXXMZLSEB2GQZJANRQXU6JAMRXWOLQ="
    let decoded = base32Decode(encoded)
    var isEqual = true
    for i, c in str:
        if decoded[i] != (uint8)(c):
            isEqual = false
            break
    doAssert isEqual, "Test for common.base32Decode() failed"

proc testBase32Encode() =
    let str = "The quick brown fox jumps over the lazy dog."
    let correctEncoding = "KRUGKIDROVUWG2ZAMJZG653OEBTG66BANJ2W24DTEBXXMZLSEB2GQZJANRQXU6JAMRXWOLQ="
    let encoded = base32Encode(str)
    doAssert encoded == correctEncoding, "Test for common.testBase32Encode() failed"

testIntToBytes()
testBytesToInt()
testBase32Decode()
testBase32Encode()