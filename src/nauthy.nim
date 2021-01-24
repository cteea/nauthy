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
        initialCounter: uint64
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

proc initHotp*(key: string | Bytes, b32Decode: bool = false, length: OtpValueLen = 6, hashFunc: HashFunc = sha1Hash): Hotp =
    ## Constructs a new HOTP.
    if b32Decode:
        let encoded: string = key.map(b => chr(b.byte) & "").join("")
        let decoded = base32Decode(encoded)
        result = (decoded, length, hashFunc, 0'u64, nil)
    else:
        let key: Bytes = key.map(c => byte(c))
        result = (key, length, hashFunc, 0'u64, nil)

proc initTotp*(key: string | Bytes, b32Decode: bool = true, length: OtpValueLen = 6, interval: TimeInterval = 30,
              hashFunc: HashFunc = sha1Hash, t0: EpochSecond = 0,): Totp =
    ## Constructs a new TOTP.
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
    ## Getter to extract account name from URI.
    result = uri.accountname.encodeUrl(usePlus=false)

proc getIssuer*(uri: Uri): string =
    ## Getter to extranct issuer from URI.
    result = uri.issuer.encodeUrl(usePlus=false)

proc otpFromUri*(uri: string): Otp =
    ## Initialize HOTP/TOTP from a URI.
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
    # let algorithm = params["algorithm"]
    let digits = if params.hasKey("digits"): (OtpValueLen)(params["digits"].parseInt) else: (OtpValueLen)(6)
    var accname = if label.len == 2: label[1] else: label[0]
    accname = accname.strip()
    if otpType == HotpT:
        let counter = params["counter"].parseInt
        var hotp = initHotp(secret.base32Decode(autoFixPadding=true), false, digits) # TODO: currently ignoring algorithm param
        let uri = newUri(issuer, accname)
        hotp.uri = uri
        hotp.initialCounter = (uint64)(counter)
        result = Otp(otpType: HotpT, hotp: hotp)
    else:
        let period = if params.hasKey("period"): (TimeInterval)(params["period"].parseInt) else: (TimeInterval)(30)
        var totp = initTotp(secret.base32Decode(autoFixPadding=true), false, digits, period) # TODO: currently ignoring algorithm param
        let uri = newUri(issuer, accname)
        totp.uri = uri
        result  = Otp(otpType: TotpT, totp: totp)

proc buildUri*(hotp: Hotp): string =
    ## Build URI from HOTP
    doAssert not hotp.uri.isNil
    doAssert not hotp.uri.getIssuer.isEmptyOrWhitespace
    doAssert not hotp.uri.getName.isEmptyOrWhitespace
    let issuer = hotp.uri.getIssuer.decodeUrl(decodePlus=false)
    let accountname = hotp.uri.getName.decodeUrl(decodePlus=false)
    let label = issuer.encodeUrl(usePlus=false) & "%3A" & accountname.encodeUrl(usePlus=false)
    let secret = hotp.key.base32Encode(ignorePadding=true)
    let algorithm = "SHA1" # TODO: currently only sha1 is available
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
    ## Build URI from TOTP
    doAssert not totp.uri.isNil
    doAssert not totp.uri.getIssuer.isEmptyOrWhitespace
    doAssert not totp.uri.getName.isEmptyOrWhitespace
    let issuer = totp.uri.getIssuer.decodeUrl(decodePlus=false)
    let accountname = totp.uri.getName.decodeUrl(decodePlus=false)
    let label = issuer.encodeUrl(usePlus=false) & "%3A" & accountname.encodeUrl(usePlus=false)
    let secret = totp.key.base32Encode(ignorePadding=true)
    let algorithm = "SHA1" # TODO: currently only sha1 is available
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

proc getHotp(key: Bytes, counter: SomeUnsignedInt, digits: OtpValueLen = 6, hash: HashFunc = sha1Hash): string =
    ## Generates HOTP value from `key` and `counter`.
    let counter = (uint64)(counter)
    let c: Bytes = intToBytes(counter)
    let mac: Bytes = hmacX(key, c, hash)
    let i: int = int(mac[^1]) mod 16
    var truncated: uint64 = bytesToint(mac[i..i+3]) mod uint64(2^31)
    truncated = truncated mod uint64(10 ^ digits)
    result = align($truncated, digits, '0')

proc getTotp(key: Bytes, digits: OtpValueLen = 6, interval: TimeInterval = 30,
           hash: HashFunc = sha1Hash, now: EpochSecond = (EpochSecond)(epochTime()), t0: EpochSecond = 0): string =
    ## Generates TOTP value from `key` using `t0` as the initial point in time
    ## to begin counting the time steps and the interval of each time step is
    ## 30 seconds by default. `t0` is Unix epoch so it is set to 0 by default.
    let c = (now - t0) div (EpochSecond)(interval)
    result = getHotp(key, c.uint64, digits, hash)

proc at*(hotp: Hotp, counter: SomeInteger): string =
    ## HOTP value at `counter`.
    doAssert counter >= 0, "value for `counter` must not be negative"
    result = getHotp(hotp.key, (uint64)(counter), hotp.length, hotp.hashFunc)

proc at*(totp: Totp, now: EpochSecond = (uint64)(epochTime())): string =
    ## TOTP value at time `now`. If `now` is not specified, the current epoch time is used instead.
    result = getTotp(totp.key, totp.length, totp.interval, totp.hashFunc, now, totp.t0)

proc verify*(hotp: Hotp, value: string, counter: SomeInteger): bool =
    ## Verify that the HOTP value for `counter` is correct.
    result = value == hotp.at(counter)

proc verify*(totp: Totp, value: string, now: EpochSecond = (uint64)(epochTime())): bool =
    ## Verify that the TOTP value for `now` is correct.
    result = value == totp.at(now)

proc randomBase32*(): string =
    ## Generates a random 16-characters Base-32 encoded string.
    ## Compatible with other OTP apps such as Google Authenticator, Authy, etc...
    randomize()
    for i in 1..16:
        let pick = $sample(b32Table)
        result = result & pick

# TODO: https://github.com/google/google-authenticator/wiki/Key-Uri-Format