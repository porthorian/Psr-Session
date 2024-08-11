
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
	* Session id must be unpredicatable and random enough to prevent guessing attacks.
	* Session id must provide at least 64 bits of entropy
		* If the crypytographically secure pseudorandom number generator is good than this is estimated to be half the length of the session id.
		* See [Session Id Properties](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-id-properties) for more information.

# 3. Specification

## 3.1 Session

```php
<?php declare(strict_types=1);

/**
 * All methods must follow the below guidelines
 * MUST NOT emit any sort of headers.
 */
interface SessionInterface
{
	/**
	 * TBD if this should actually even belong in here.
	 * If this gets removed from this interface, than we would need to make a change to the function start.
	 * As this would currently store the max age of the session.
	 */
	public function getCookieParams() : SessionCookieInterface;
	public function withCookieParams(SessionCookieInterface $config) : self;

	/**
	 * MUST return the name of the session identifer.
	 * This for example would be used as the cookie name.
	 *
	 * @return string
	 */
	public function getName() : string;

	/**
	 * This method MUST be implemented in such that they retain the internal state of the current session
	 * and return an instance that contains the changed state.
	 */
	public function withName(string $name) : self;

	public function getRepository() : RepositoryInterface;

	/**
	 * This method MUST be implemented in such that they retain the internal state of the current session
	 * and return an instance that contains the changed state.
	 */
	public function withRepository(RepositoryInterface $repo) : self;

	/**
	 * Return Unix Timestamp when the session token was issued.
	 *
	 * MUST return the timestamp in seconds.
	 * RECOMMENDED throw exception if session is not active.
	 *
	 * @return int
	 */
	public function getIssuedAt() : int;

	/**
	 * MUST return true if the session has been activated and is being used by the object.
	 * MUST return false if the session has not been activated and isn't usable by the object.
	 * This does not mean the session doesn't exist.
	 *
	 * @return bool
	 */
	public function isActive() : bool;

	/**
	 * MUST return false if the session does not exist.
	 * MUST return true if the session exists and has been "resumed".
	 *
	 * @throws SessionExceptionInterface
	 * @return bool
	 */
	public function resume(string $session_id) : bool;

	/**
	 * RECOMMENDED throw exception if the session is already active.
	 * MUST generate the session id
	 * MUST generate the issued time of the id
	 * MUST consider the object active after running if no errors occur.
	 * MUST throw exception if session fails to start.
	 *
	 * @throws SessionException
	 * @return void
	 */
	public function start() : void;

	/**
	 * RECOMMENDED throw exception if session is not active.
	 * MUST destroy the session_id
	 * MUST destroy all session data related to the session_id
	 *
	 * @return void
	 */
	public function destroy() : void;

	/**
	 * Returns all session data related to the session id;
	 *
	 * MUST throw exception if session is not active.
	 *
	 * @return array
	 */
	public function all() : array;

	/**
	 * RECOMMENDED throw exception if the session is not active.
	 * MUST get data related to the current active session
	 *
	 * @return mixed
	 */
	public function get(string $key, mixed $default = null) : mixed;

	/**
	 * RECOMMENDED throw exception if the session is not active.
	 * MUST set data related to the current active session
	 *
	 * @return void
	 */
	public function set(string $key, mixed $value) : void;

	/**
	 * RECOMMENDED throw exception if the session is not active.
	 * MUST determine if the key value exists in the current active session.
	 *
	 * @return bool
	 */
	public function has(string $key) : bool;

	/**
	 * MUST remove a value from the session.
	 * RECOMMENDED throw exception if session is not active.
	 *
	 * @return void
	 */
	public function remove(string $key) : void;

	/**
	 * RECOMMENDED throw exception if the session is not active.
	 * MUST regenerate the current session_id while maintaining all current session attributes.
	 * MUST throw SessionExceptionInterface if session fails to move to the new session id.
	 *
	 * @param bool $destroy - Whether to delete the old session or leave it to garbage collection.
	 * @throws SessionExceptionInterface
	 * @return void
	 */
	public function migrate(bool $destroy = false) : void;

	/**
	 * RECOMMENDED throw an Exception if the Session is not active.
	 * MUST regenerate the current session id on the active object.
	 * MUST maintain the existance of the old session id with any old data.
	 * MUST maintain the current session values, but generate a new session id.
	 * MUST update a UNIX Timestamp for the original issued_at.
	 *
	 * @return void
	 */
	public function regenerateId() : void;

	/**
	 * MUST return the current active session id that is being used by the object.
	 * MUST return null if the session is not active.
	 *
	 * @return string|null
	 */
	public function getId() : ?string;

	/**
	 * RECOMMENDED throw exception if session is not active.
	 * MUST store the session using an instance of SessionRepositoryInterface
	 * MUST throw an exception if session fails to store.
	 *
	 * @throws SessionExceptionInterface
	 * @return void
	 */
	public function save() : void;
}

```

## 3.2 Cookies

This section is up in the air and not sure what to really do with it. As this would mostly fall under a PER rather than a PSR?

Its also possible this shouldn't even belong in a PSR for sessions.

For instance 15 years ago there was no "Secure" parameter to cookies.
Another instance is SameSite there was nothing in that regard 10+ years ago.
https://datatracker.ietf.org/doc/html/draft-west-first-party-cookies-07
```php
<?php declare(strict_types=1);

interface SessionCookieInterface
{
	/**
	 * MUST give the total length of the session in seconds.
	 *
	 * @return int
	 */
	public function getLifetime() : int;
	public function withLifetime(int $lifetime) : self;


	/**
	 * MUST give the path to a cookie
	 *
	 * @return string
	 */
	public function getPath() : string;
	public function withPath(string $path) : self;

	public function getDomain() : string;
	public function withDomain(string $domain) : self;

	public function getSecure() : bool;
	public function withSecure(bool $secure) : self;

	public function getHttpOnly() : bool;
	public function withHttpOnly(bool $http_only) : self;

	public function getSameSite() : SameSiteEnum;
	public function withSameSite(SameSiteEnum $samesite) : self;

	/**
	 * @see https://datatracker.ietf.org/doc/html/rfc7234#section-5.3
	 * @see https://datatracker.ietf.org/doc/html/rfc7231#section-7.1.1.1
	 *
	 * @return string
	 */
	public function createCookieString(SessionInterface $session) : string;
}

// Generic Enum again not sure what to do with.
enum SameSiteEnum
{
	case STRICT;
	case LAX;
	case NONE;

	public function toString() : string
	{
		return match ($this)
		{
			self::STRICT => 'STRICT',
			self::LAX => 'LAX',
			self::NONE => 'NONE'
		};
	}
}
```

## 3.3 Headers

### TBD

## 3.4 Factory
```php
<?php declare(strict_types=1);

interface FactoryInterface
{
	public function createSession(string $session_name, ?SessionCookieInterface $cookie_params = null, ?RepositoryInterface $repo = null) : SessionInterface;
}
```

## 3.5 Repository

```php
<?php declare(strict_types=1);

interface RepositoryInterface
{
	public function store(SessionInterface $session) : void;

	/**
	 * MUST query the session based on the session id.
	 * MUST set attributes related to the session against the QueryInterface
	 * MUST set the session data against the QueryInterface
	 * 
	 * MUST return null if no session id exists.
	 * 
	 * @return QueryInterface
	 */
	public function query(SessionInterface $session) : ?QueryInterface;

	public function delete(SessionInterface $session) : void;
}
```

```php
<?php declare(strict_types=1);

/**
 * Queries are considered immutable; all methods that might change state MUST
 * be implemented such that they retain the internal state of the current
 * query and return an instance that contains the changed state.
 */
interface QueryInterface
{
	/**
	 * Attributes would be defined as things that would be needed to check the state of the session data.
	 * This could be used in aiding developers on how to decrypt a session for example, or store when the session was issued as another example.
	 */
	public function getAttributes() : array;

	/**
	 * This method MUST be implemented in such that they retain the internal state of the current session
	 * and return an instance that contains the changed state.
	 */
	public function withAttributes(array $attributes) : self;

	/**
	 * MUST return ONLY the session data.
	 */
	public function getData() : array;

	/**
	 * This method MUST be implemented in such that they retain the internal state of the current session
	 * and return an instance that contains the changed state.
	 */
	public function withData(array $data) : self;
}
```

## 3.6 Exception
```php
<?php declare(strict_types=1);

/**
 * Generic Catch all
 */
interface SessionExceptionInterface
{
}
```

```php
<?php declare(strict_types=1);

/**
 * SHOULD generally be thrown when a certain action that requires activity is called.
 */
interface NotActiveExceptionInterface extends SessionExceptionInterface
{
}
