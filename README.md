# nauthy - one-time password library for nim

nauthy is a Nim library for generating and verifying one-time passwords: HOTP
(RFC4226) and TOTP (RFC6238). Various hash modes are supported: md5, sha1,
sha256 and sha512. Support for  [key URI](https://github.com/google/google-authenticator/wiki/Key-Uri-Format) is also included.
