import math, strutils, times, sequtils, sugar
include "./hashfuncs"

type
    OtpValueLen* = range[6..10]
    TimeInterval* = range[1..int.high]
    EpochSecond* = BiggestUInt

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

proc newHotp*(key: string | Bytes, b32Decode: bool = false, length: OtpValueLen = 6, hashFunc: HashFunc = sha1Hash): Hotp =
    ## Constructs a new HOTP.
    if b32Decode:
        let encoded: string = key.map(b => chr(b.byte) & "").join("")
        let decoded = base32Decode(encoded)
        result = (decoded, length, hashFunc)
    else:
        let key: Bytes = key.map(c => byte(c))
        result = (key, length, hashFunc)

proc newTotp*(key: string | Bytes, b32Decode: bool = true, length: OtpValueLen = 6, interval: TimeInterval = 30,
              hashFunc: HashFunc = sha1Hash, t0: EpochSecond = 0,): Totp =
    ## Constructs a new TOTP.
    if b32Decode:
        let encoded: string = key.map(b => chr(b.byte) & "").join("")
        let decoded = base32Decode(encoded)
        result = (decoded, length, interval, hashFunc, t0)
    else:
        let key: Bytes = key.map(c => byte(c))
        result = (key, length, interval, hashFunc, t0)

proc hotp(key: Bytes, counter: BiggestUInt, digits: OtpValueLen = 6, hash: HashFunc = sha1Hash): string =
    ## Generates HOTP value from `key` and `counter`.
    let c: Bytes = intToBytes(counter)
    let mac: Bytes = hmacX(key, c, hash)
    let i: int = int(mac[^1]) mod 16
    var truncated: uint64 = bytesToint(mac[i..i+3]) mod uint64(2^31)
    truncated = truncated mod uint64(10 ^ digits)
    result = align($truncated, digits, '0')

proc totp(key: Bytes, digits: OtpValueLen = 6, interval: TimeInterval = 30,
           hash: HashFunc = sha1Hash, now: EpochSecond = (EpochSecond)(epochTime()), t0: EpochSecond = 0): string =
    ## Generates TOTP value from `key` using `t0` as the initial point in time
    ## to begin counting the time steps and the interval of each time step is
    ## 30 seconds by default. `t0` is Unix epoch so it is set to 0 by default.
    let c = (now - t0) div (EpochSecond)(interval)
    result = hotp(key, c.uint64, digits, hash)

proc at*(hotp: Hotp, counter: BiggestUInt): string =
    ## HOTP value at `counter`.
    result = hotp(hotp.key, counter, hotp.length, hotp.hashFunc)

proc at*(totp: Totp, now: EpochSecond = (uint64)(epochTime())): string =
    ## TOTP value at time `now`. If `now` is not specified, the current epoch time is used instead.
    result = totp(totp.key, totp.length, totp.interval, totp.hashFunc, now, totp.t0)