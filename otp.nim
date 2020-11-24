import math
import strutils
import times
import ./common
import ./hmac


proc hotp*(key: Bytes, counter: uint64, digits = 6): string =
    ## Generates HOTP value from `key` and `counter`.
    let c: Bytes = intToBytes(counter)
    let mac: Bytes = hmacSha1(key, c)
    let i: int = int(mac[^1]) mod 16
    var truncated: uint64 = bytesToint(mac[i..i+3]) mod uint64(2^31)
    truncated = truncated mod uint64(10 ^ 6)
    result = align($truncated, digits, '0')

proc totp*(key: Bytes, digits = 6, tk: int64 = 30, t0: int64 = 0): string =
    ## Generates TOTP value from `key` using `t0` as the initial point in time
    ## to start counting the time steps and the duration of each time step is
    ## `tk` seconds. `t0` is Unix epoch so it is set to 0 by default.
    let c = (int64(epochTime()) - t0) div tk
    result = hotp(key, c.uint64)

proc gAuthenticatorTOTP*(key: string): string =
    ## Google Authenticator compatible TOTP where the 'key' is given as a
    #base32 string.
    result = totp(key.base32Decode)