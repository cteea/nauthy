## A library for generating and verifying one-time passwords (OTP).
## ``nauthy`` library implements counter-based OTP (RFC4226) and time-based OTP (RFC6238).
## Various hash modes are supported: `MD5`, `SHA1`, `SHA256` and `SHA512` as
## well as custom hash functions.
## 
## Basic usage
## ===========
## 
## Some examples to get started:
## 
## .. code-block::
##   import nauthy
##   
##   # Construct a new TOTP with a base-32 encoded key.
##   var totp = initTotp("HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ")
##   # Print out the current totp value
##   echo totp.now()
## 
##   # Construct a new TOTP from a URI.
##   var otp = otpFromUri(
##      "otpauth://totp/ACME%20Co:john@example.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co"
##   )
##   echo otp.totp.now() 
## 
##   # Build a URI from a TOTP
##   totp.uri = newUri(issuer: "ACME Co", accountname: "alice@example.com")
##   echo totp.buildUri()
##   

import math, strutils, times, sequtils, sugar, random, uri, tables
include "./hashfuncs"

type
    OtpValueLen* = range[6..10]
    TimeInterval* = range[1..int.high]
    EpochSecond* = BiggestUInt

    OtpType* = enum
        HotpT = "hotp",
        TotpT = "totp"

    Uri* = ref object
        issuer: string
        accountname: string

    Hotp* = tuple
        key: Bytes
        length: OtpValueLen
        hashFunc: HashFunc
        initialCounter: int
        uri: Uri
    
    Totp* = tuple
        key: Bytes
        length: OtpValueLen
        interval: TimeInterval
        hashFunc: HashFunc
        t0: EpochSecond
        uri: Uri
    
    Otp* = ref object
        case otpType*: OtpType
        of HotpT: hotp*: Hotp
        of TotpT: totp*: Totp

proc `$`*(u: Uri): string =
    result = "{issuer: $#, accountname: $#}" % [u.issuer, u.accountname]

proc initHotp*(key: string | Bytes, b32Decode: bool = false, length: OtpValueLen = 6, hashFunc: HashFunc = sha1Hash): Hotp =
    ## Constructs a new HOTP. `sha1Hash` is the default but other hash modes are also available:
    ## `md5Hash`, `sha256Hash` and `sha512Hash`. Custom hash functions are also accepted. If the
    ## given `key` is base32-encoded, give the `b32Decode` argument as `true`.
    if b32Decode:
        let encoded: string = key.map(b => chr(b.byte) & "").join("")
        let decoded = base32Decode(encoded)
        result = (decoded, length, hashFunc, 0, nil)
    else:
        let key: Bytes = key.map(c => byte(c))
        result = (key, length, hashFunc, 0, nil)

proc initTotp*(key: string | Bytes, b32Decode: bool = true, length: OtpValueLen = 6, interval: TimeInterval = 30,
              hashFunc: HashFunc = sha1Hash, t0: EpochSecond = 0,): Totp =
    ## Constructs a new TOTP. `sha1Hash` is the default but other hash modes are also available:
    ## `md5Hash`, `sha256Hash` and `sha512Hash`. Custom hash functions are also accepted. If the
    ## given `key` is base32-encoded, give the `b32Decode` argument as `true`.
    if b32Decode:
        let encoded: string = key.map(b => chr(b.byte) & "").join("")
        let decoded = base32Decode(encoded)
        result = (decoded, length, interval, hashFunc, t0, nil)
    else:
        let key: Bytes = key.map(c => byte(c))
        result = (key, length, interval, hashFunc, t0, nil)

proc newUri*(issuer: string, accountname: string): Uri =
    ## Constructs a new URI.
    doAssert not issuer.isEmptyOrWhitespace
    doAssert not issuer.isEmptyOrWhitespace
    let issuer = issuer.decodeUrl(decodePlus=false)
    let accountname = accountname.decodeUrl(decodePlus=false)
    result = Uri(issuer: issuer, accountname: accountname)

proc getName*(uri: Uri): string =
    ## Extract account name from a URI.
    result = uri.accountname.encodeUrl(usePlus=false)

proc getIssuer*(uri: Uri): string =
    ## Extract issuer from a URI.
    result = uri.issuer.encodeUrl(usePlus=false)

proc otpFromUri*(uri: string): Otp =
    ## Initialize HOTP/TOTP from a URI.
    runnableExamples:
        let otp = otpFromUri(
            "otpauth://totp/ACME:john@dot.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME"
            )
        var totp = otp.totp
    let uri = parseUri(uri)
    doAssert uri.scheme == "otpauth", "invalid URI"
    let otpType = parseEnum[OtpType](uri.hostname)
    let label = uri.path[1..^1].decodeUrl(decodePlus=false).split(':')
    let parameters = uri.query.split('&')
    var params = initTable[string, string]()
    for p in parameters:
        let s = p.split('=')
        params[s[0]] = s[1]
    let secret = params["secret"]
    let issuer = params["issuer"].strip()
    let algorithm = if params.hasKey("algorithm"): parseEnum[Algorithm](params["algorithm"]) else: SHA1
    let digits = if params.hasKey("digits"): (OtpValueLen)(params["digits"].parseInt) else: (OtpValueLen)(6)
    var accname = if label.len == 2: label[1] else: label[0]
    accname = accname.strip()
    if otpType == HotpT:
        let counter = params["counter"].parseInt
        var hotp = initHotp(secret.base32Decode(autoFixPadding=true), false, digits, algorithms[algorithm])
        let uri = newUri(issuer, accname)
        hotp.uri = uri
        hotp.initialCounter = counter
        result = Otp(otpType: HotpT, hotp: hotp)
    else:
        let period = if params.hasKey("period"): (TimeInterval)(params["period"].parseInt) else: (TimeInterval)(30)
        var totp = initTotp(secret.base32Decode(autoFixPadding=true), false, digits, period, algorithms[algorithm])
        let uri = newUri(issuer, accname)
        totp.uri = uri
        result  = Otp(otpType: TotpT, totp: totp)

proc buildUri*(hotp: Hotp): string =
    ## Build URI from HOTP.
    doAssert not hotp.uri.isNil
    doAssert not hotp.uri.getIssuer.isEmptyOrWhitespace
    doAssert not hotp.uri.getName.isEmptyOrWhitespace
    let issuer = hotp.uri.getIssuer.decodeUrl(decodePlus=false)
    let accountname = hotp.uri.getName.decodeUrl(decodePlus=false)
    let label = issuer.encodeUrl(usePlus=false) & "%3A" & accountname.encodeUrl(usePlus=false)
    let secret = hotp.key.base32Encode(ignorePadding=true)
    doAssert not hotp.hashFunc.name.isEmptyOrWhitespace()
    let algorithm = hotp.hashFunc.name.toUpperAscii()
    let digits = $hotp.length
    let counter = $hotp.initialCounter
    let params = encodeQuery({"secret": secret, "issuer": issuer, "algorithm": algorithm,
                              "digits": digits, "counter": counter}, usePlus=false)
    var uri = initUri()
    uri.scheme = "otpauth"
    uri.hostname = "hotp"
    uri.path = "/" & label
    uri.query = params
    result = $uri

proc buildUri*(totp: Totp): string =
    ## Build URI from TOTP.
    doAssert not totp.uri.isNil
    doAssert not totp.uri.getIssuer.isEmptyOrWhitespace
    doAssert not totp.uri.getName.isEmptyOrWhitespace
    let issuer = totp.uri.getIssuer.decodeUrl(decodePlus=false)
    let accountname = totp.uri.getName.decodeUrl(decodePlus=false)
    let label = issuer.encodeUrl(usePlus=false) & "%3A" & accountname.encodeUrl(usePlus=false)
    let secret = totp.key.base32Encode(ignorePadding=true)
    doAssert not totp.hashFunc.name.isEmptyOrWhitespace()
    let algorithm = totp.hashFunc.name.toUpperAscii()
    let digits = $totp.length
    let period = $totp.interval
    let params = encodeQuery({"secret": secret, "issuer": issuer, "algorithm": algorithm,
                              "digits": digits, "period": period}, usePlus=false)
    var uri = initUri()
    uri.scheme = "otpauth"
    uri.hostname = "totp"
    uri.path = "/" & label
    uri.query = params
    result = $uri

proc `$`*(hotp: Hotp): string =
    ## This is the same as ``hotp.buildUri()``.
    result = hotp.buildUri()

proc `$`*(totp: Totp): string =
    ## This is the same as ``totp.buildUri()``.
    result = totp.buildUri()

proc getHotp(key: Bytes, counter: SomeUnsignedInt, digits: OtpValueLen = 6, hash: HashFunc = sha1Hash): string =
    ## Generates HOTP value from `key` and `counter`.
    let counter = (uint64)(counter)
    let c: Bytes = intToBytes(counter)
    let mac: Bytes = hmacX(key, c, hash)
    let i: int = int(mac[^1]) mod 16
    var truncated: uint64 = bytesToint(mac[i..i+3]) mod uint64(2^31)
    truncated = truncated mod uint64(10 ^ digits)
    result = align($truncated, digits, '0')

proc currentTime(): EpochSecond = (EpochSecond)(epochTime())

proc getTotp(key: Bytes, digits: OtpValueLen = 6, interval: TimeInterval = 30,
           hash: HashFunc = sha1Hash, now: EpochSecond = currentTime(), t0: EpochSecond = 0): string =
    ## Generates TOTP value from `key` using `t0` as the initial point in time
    ## to begin counting the time steps and the interval of each time step is
    ## 30 seconds by default. `t0` is Unix epoch so it is set to 0 by default.
    let c = (now - t0) div (EpochSecond)(interval)
    result = getHotp(key, c.uint64, digits, hash)

proc at*(hotp: Hotp, counter: SomeInteger): string =
    ## Get HOTP value at `counter`.
    doAssert counter >= 0, "value for `counter` must not be negative"
    result = getHotp(hotp.key, (uint64)(counter), hotp.length, hotp.hashFunc)

proc at*(totp: Totp, utime: EpochSecond): string =
    ## Get TOTP value at time `utime`.
    result = getTotp(totp.key, totp.length, totp.interval, totp.hashFunc, utime, totp.t0)

proc now*(totp: Totp): string =
    ## Get TOTP value at current time.
    result = totp.at(currentTime())

proc verify*(hotp: Hotp, value: string, counter: SomeInteger): bool =
    ## Verify that the given HOTP `value` is correct.
    result = value == hotp.at(counter)

proc verify*(totp: Totp, value: string, now: EpochSecond = currentTime()): bool =
    ## Verify that the given TOTP `value` is correct.
    result = value == totp.at(now)

proc randomBase32*(): string =
    ## Generates a random 16-characters Base-32 encoded string.
    ## Compatible with other OTP apps such as Google Authenticator and Authy.
    randomize()
    for i in 1..16:
        let pick = $sample(b32Table)
        result = result & pick
