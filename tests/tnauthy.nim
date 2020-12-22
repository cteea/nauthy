import sequtils, sugar, strutils
import "../src/nauthy"

proc testHotp() =
    ## Test HOTP implementation using the test values provided in RFC4226.
    let secret: Bytes = "12345678901234567890".map(c => (byte)(c))
    let hotp = newHotp(secret)
    let correctValues = ["755224", "287082", "359152", "969429", "338314",
                         "254676", "287922", "162583", "399871", "520489"]
    for i in 0..9:
        let counter = (uint64)(i)
        let correct = correctValues[i]
        let value = hotp.at(counter)
        doAssert value == correct, "Test for otp.hotp() failed; result = $1, correct_value = $2" % [$value, $correct]

proc testTotp() =
    ## Test TOTP implementation using the test values provided in RFC6238.
    let secret: Bytes = "12345678901234567890".map(c => (byte)(c))
    let totp = newTotp(secret, 8)
    let correctValues = [(59'i64, "94287082"), (1111111109'i64, "07081804"), (1111111111'i64, "14050471"),
                         (1234567890'i64, "89005924"), (2000000000'i64, "69279037"), (20000000000'i64, "65353130")]
    for (time, correct) in correctValues:
        let value = totp.at(time)
        doAssert value == correct, "Test for otp.totp() failed; result = $1, correct_value = $2" % [$value, $correct]

testHotp()
testTotp()