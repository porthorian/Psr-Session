
The interfaces described in this document are abstractions around HTTP messages and the elements composing them.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

## References
* [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119)
* ~~[RFC 7231](https://www.rfc-editor.org/rfc/rfc7231)~~ Obsolete - Replaced by RFC 9110
* ~~[RFC 7234](https://www.rfc-editor.org/rfc/rfc7234)~~ Obsolete - Replaced by RFC 9110
* [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110)
	* [Date Time Formats](https://www.rfc-editor.org/rfc/rfc9110#name-date-time-formats)
* [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
* [DateTime Cookie Change](https://php.watch/versions/8.2/DateTime-COOKIE-value-change)

# 1. Problem

# 2. Security
* Session id length should be no shorter than 128 bits (16 bytes)
	* Session id must be unpredicatable and random enough to prevent guessing attachs.
	* Session id must provide at least 64 bits of entropy
		* If the crypytographically secure pseudorandom number generator is good than this is estimated to be half the length of the session id.
		* See [Session Id Properties](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-id-properties) for more information.

# 3. Specification

## 3.1 Session

## 3.2 Cookies

## 3.3 Headers

## 3.4 Factory
