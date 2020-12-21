import sequtils, sugar, strutils
import "../otp", "../common"

proc testHotp() =
    ## Test HOTP implementation using the test values provided in RFC4226.
    let secret: Bytes = "12345678901234567890".map(c => (byte)(c))
    let correctValues = ["755224", "287082", "359152", "969429", "338314",
                         "254676", "287922", "162583", "399871", "520489"]
    for i in 0..9:
        let counter = (uint64)(i)
        let correct = correctValues[i]
        let value = hotp(secret, counter)
        doAssert value == correct, "Test for otp.hotp() failed; result = $1, correct_value = $2" % [$value, $correct]

testHotp()