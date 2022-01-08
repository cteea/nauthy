# nauthy - one-time password library for nim

nauthy is a Nim library for generating and verifying one-time passwords: HOTP
(RFC4226) and TOTP (RFC6238). Various hash modes are supported: md5, sha1,
sha256 and sha512. Support for [key URI](https://github.com/google/google-authenticator/wiki/Key-Uri-Format) is also included.

Basic example:
```nim
import nauthy
 
# Construct a new TOTP with a base-32 encoded key.
var totp = initTotp("HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ")
# Print out the current totp value
echo totp.now()

# Construct a new TOTP from a URI.
var otp = otpFromUri(
   "otpauth://totp/ACME%20Co:john@example.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co"
)
echo otp.totp.now() 

# Build a URI from a TOTP
totp.uri = newUri("Example issuer", "accountname@example.com")
echo totp.buildUri()
```
