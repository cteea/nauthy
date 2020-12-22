import math
import strutils
import times
import "./common"
import "./hmac"

type
    OtpValueLen = range[6..10]
    TimeInterval = range[1..int.high]

    Hotp* = tuple
        key: Bytes
        counter: uint64
        length: OtpValueLen
        hashFunc: HashFunc
    
    Totp* = tuple
        key: Bytes
        length: OtpValueLen
        interval: TimeInterval
        hashFunc: HashFunc
        t0: uint64
        timeNow: uint64

proc newHotp*(key: Bytes, counter: uint64 = 0, length: OtpValueLen = 6, hashFunc: HashFunc = sha1Hash): Hotp =
    result = (key, counter, length, hashFunc)

proc newTotp*(key: Bytes, length: OtpValueLen = 6, interval: TimeInterval = 30,
              hashFunc: HashFunc = sha1Hash, t0: uint64 = 0, now: uint64 = (uint64)(epochTime())): Totp =
    result = (key, length, interval, hashFunc, t0, now)

proc hotp*(key: Bytes, counter: uint64, digits = 6, hmac: HmacFunc = hmacSha1): string =
    ## Generates HOTP value from `key` and `counter`.
    let c: Bytes = intToBytes(counter)
    let mac: Bytes = hmac(key, c)
    let i: int = int(mac[^1]) mod 16
    var truncated: uint64 = bytesToint(mac[i..i+3]) mod uint64(2^31)
    truncated = truncated mod uint64(10 ^ digits)
    result = align($truncated, digits, '0')

proc totp*(key: Bytes, digits = 6, interval: int64 = 30, hmac: HmacFunc = hmacSha1, now: int64 = (int64)(epochTime()), t0: int64 = 0): string =
    ## Generates TOTP value from `key` using `t0` as the initial point in time
    ## to begin counting the time steps and the interval of each time step is
    ## 30 seconds by default. `t0` is Unix epoch so it is set to 0 by default.
    let c = (now - t0) div interval
    result = hotp(key, c.uint64, digits, hmac)

proc b32totp*(key: string, digits = 6, inteval: int64 = 30): string =
    ## Google Authenticator compatible TOTP where the 'key' is given as a
    ## Base-32 encoded string.
    result = totp(key.base32Decode)