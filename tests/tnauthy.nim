import sequtils, sugar, strutils, random
include "../src/utils"
import "../src/nauthy"

proc testHotpValidRFC() =
    ## Test HOTP implementation using the valid test values provided in RFC4226.
    
    # Test by initializing a Hotp with a string.
    let secretStr: string = "12345678901234567890"
    let hotp = newHotp(secretStr)
    let correctValues = ["755224", "287082", "359152", "969429", "338314",
                         "254676", "287922", "162583", "399871", "520489"]
    for i in 0..9:
        let counter = (uint64)(i)
        let correct = correctValues[i]
        let value = hotp.at(counter)
        let errMsg = "Test for Hotp.at($1) failed; result = $2, correct_value = $3" % [$counter, $value, $correct]
        doAssert value == correct, errMsg

    # Test by initializing a Hotp with a sequence of bytes.
    let secretBytes: Bytes = "12345678901234567890".map(c => (byte)(c))
    let hotp2 = newHotp(secretBytes)
    for i in 0..9:
        let counter = (uint64)(i)
        let correct = correctValues[i]
        let value = hotp2.at(counter)
        let errMsg = "Test for Hotp.at($1) failed; result = $2, correct_value = $3" % [$counter, $value, $correct]
        doAssert value == correct, errMsg
    
    # Test by initializing a Hotp with a base32 encoded string.
    let secretStrEncoded: string = base32Encode("12345678901234567890")
    let hotp3 = newHotp(secretStrEncoded, true)
    for i in 0..9:
        let counter = (uint64)(i)
        let correct = correctValues[i]
        let value = hotp3.at(counter)
        let errMsg = "Test for Hotp.at($1) failed; result = $2, correct_value = $3" % [$counter, $value, $correct]
        doAssert value == correct, errMsg
    
    # Test by initializing a Hotp with a sequence of bytes that is base32 encoded.
    let secretBytesEncoded: Bytes = secretStrEncoded.map(c => byte(c))
    let hotp4 = newHotp(secretBytesEncoded, true)
    for i in 0..9:
        let counter = (uint64)(i)
        let correct = correctValues[i]
        let value = hotp4.at(counter)
        let errMsg = "Test for Hotp.at($1) failed; result = $2, correct_value = $3" % [$counter, $value, $correct]
        doAssert value == correct, errMsg

proc testTotpValidRFC() =
    ## Test TOTP implementation using the valid test values provided in RFC6238.
    
    # Test by initializing a Totp with a sequence of bytes.
    let secret: Bytes = "12345678901234567890".map(c => (byte)(c))
    let totp = newTotp(secret, false, 8)
    let correctValues = [(59'u64, "94287082"), (1111111109'u64, "07081804"), (1111111111'u64, "14050471"),
                         (1234567890'u64, "89005924"), (2000000000'u64, "69279037"), (20000000000'u64, "65353130")]
    for (time, correct) in correctValues:
        let value = totp.at(time)
        doAssert value == correct, "Test for Totp.at() failed; result = $1, correct_value = $2" % [$value, $correct]

    # Test by initializing a Totp with a string.
    let secretStr = "12345678901234567890"
    let totp2 = newTotp(secretStr, false, 8)
    for (time, correct) in correctValues:
        let value = totp2.at(time)
        doAssert value == correct, "Test for Totp.at() failed; result = $1, correct_value = $2" % [$value, $correct]

    # Test by initializing a Totp with a base32 encoded string.
    let secretStrEncoded = base32Encode("12345678901234567890")
    let totp3 = newTotp(key=secretStrEncoded, length=8)
    for (time, correct) in correctValues:
        let value = totp3.at(time)
        doAssert value == correct, "Test for Totp.at() failed; result = $1, correct_value = $2" % [$value, $correct]

    # Test by initializing a Totp with a base32 encoded sequence of bytes.
    let secretBytesEncoded: Bytes = base32Encode("12345678901234567890").map(c => byte(c))
    let totp4 = newTotp(key=secretBytesEncoded, length=8)
    for (time, correct) in correctValues:
        let value = totp4.at(time)
        doAssert value == correct, "Test for Totp.at() failed; result = $1, correct_value = $2" % [$value, $correct]

proc testHotpInvalid() =
    let hotp = newHotp("1234567890")
    doAssertRaises(AssertionDefect):
        discard hotp.at(-1)

proc testHotpVerify() =
    let hotp = newHotp("12345678901234567890")
    let correctValues = ["755224", "287082", "359152", "969429", "338314",
                         "254676", "287922", "162583", "399871", "520489"]
    for i in 0..9:
        doAssert hotp.verify(correctValues[i], i)
        randomize()
        var r = $rand(999999)
        while r == correctValues[i]: r = $rand(999999)
        doAssert not hotp.verify(r, i)

proc testTotpVerify() =
    let totp = newTotp(key="12345678901234567890".base32Encode, length=8)
    let correctValues = [(59'u64, "94287082"), (1111111109'u64, "07081804"), (1111111111'u64, "14050471"),
                         (1234567890'u64, "89005924"), (2000000000'u64, "69279037"), (20000000000'u64, "65353130")]
    for (time, correct) in correctValues:
        doAssert totp.verify(correct, time)
        randomize()
        var r = $rand(99999999)
        while r == correct: r = $rand(99999999)
        doAssert not totp.verify(r, time)

testHotpValidRFC()
testTotpValidRFC()
testHotpInvalid()
testHotpVerify()
testTotpVerify()