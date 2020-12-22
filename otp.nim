import math
import strutils
import times
import "./common"
import "./hmac"

type
    OtpValueLen = range[6..10]
    TimeInterval = range[1..int.high]
    EpochSecond = range[BiggestUInt.low..BiggestUInt.high]

    Hotp* = tuple
        key: Bytes
        length: OtpValueLen
        hashFunc: HashFunc
    
    Totp* = tuple
        key: Bytes
        length: OtpValueLen
        interval: TimeInterval
        hashFunc: HashFunc
        t0: EpochSecond

proc newHotp*(key: Bytes, length: OtpValueLen = 6, hashFunc: HashFunc = sha1Hash): Hotp =
    result = (key, length, hashFunc)

proc newTotp*(key: Bytes, length: OtpValueLen = 6, interval: TimeInterval = 30,
              hashFunc: HashFunc = sha1Hash, t0: EpochSecond = 0,): Totp =
    result = (key, length, interval, hashFunc, t0)

proc hotp*(key: Bytes, counter: uint64, digits = 6, hash: HashFunc = sha1Hash): string =
    ## Generates HOTP value from `key` and `counter`.
    let c: Bytes = intToBytes(counter)
    let mac: Bytes = hmacX(key, c, hash)
    let i: int = int(mac[^1]) mod 16
    var truncated: uint64 = bytesToint(mac[i..i+3]) mod uint64(2^31)
    truncated = truncated mod uint64(10 ^ digits)
    result = align($truncated, digits, '0')

proc totp*(key: Bytes, digits = 6, interval: int64 = 30, hash: HashFunc = sha1Hash, now: int64 = (int64)(epochTime()), t0: int64 = 0): string =
    ## Generates TOTP value from `key` using `t0` as the initial point in time
    ## to begin counting the time steps and the interval of each time step is
    ## 30 seconds by default. `t0` is Unix epoch so it is set to 0 by default.
    let c = (now - t0) div interval
    result = hotp(key, c.uint64, digits, hash)

proc b32totp*(key: string, digits = 6, inteval: int64 = 30): string =
    ## Google Authenticator compatible TOTP where the 'key' is given as a
    ## Base-32 encoded string.
    result = totp(key.base32Decode)