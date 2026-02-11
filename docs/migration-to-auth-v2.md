## Authentication v2

REST gateway version 0.16.0 introduced a set of /v2/auth paths for
authorization. It at the same time removed support for container operations
from /v1/auth because they relied on old session tokens and couldn't be used
securely. Other /v1/auth functionality was deprecated and applications are
recommended to migrate to /v2/auth for all purposes.

### Key differences

/v1/auth allowed to create bearer tokens that can be used for object
operations. For NeoFS these tokens allow to override container EACL and
make it possible for gateway to perform operations for user if bearer
token allows it to. Object creater (aka owner) is gateway in this case.
/v2/auth/bearer mostly follows the same model and allows to create the
same tokens for object operations. These tokens however is expected to
be used optionally, when container owner needs to share access with
other users, not with gateway.

To make it possible for gateway to perform operations on behalf of user
session tokens (v2) are used now, /v2/auth/session helps creating them.
Session tokens allow for both container and object operations and when
used for object operations they pass the power of attorney from user to
gateway, so object creator (for PUT operations) is user account in this case,
even though it's gateway that signs them.

Using /v2/auth is optional, any token can be created without REST gateway
itself, but there are specific requirements for these tokens and REST makes
it easier by solving protobuf serialization on its side (while signature is
created elsewhere).

### Session token flow

1. Choose who you want to trust. Use /v1/gateway to get gateway key address
   and NNS name if it has any configured. NNS names allow to use multiple
   gateways, addresses are single gateway.
2. Make a POST to /v2/auth/session, specify owner (user address), target
   (gateway address/name) and contexts (specific actions allowed to perform
   with this token).
3. The reply contains two fields, "token" and "lock". Token is what needs to
   be signed by user, any signature method known to NeoFS can be used. Lock
   is what needs to be remembered for the next request, it binds token (which
   can be treated as public data) to some data outside of it for user
   authentication at the REST gateway level.
4. Sign token.
5. Make a POST to /v2/auth/session/complete, it should contain the same token
   and lock as was returned from /v2/auth/session, then signature is passed
   via "signature" field (base64) and there are two more things required:
   public key (or verification script for N3 scheme) in "key" field and
   signature scheme used in "scheme" field. Most users with external wallets
   will use "WALLETCONNECT" here.
6. The reply contains a single "token" element that represents ready to use
   REST gateway token. Pass this token via Bearer HTTP Authentication for
   requests that need it.

#### Session token structure

REST gateway uses standard NeoFS session token with additional lock data to
prevent malicious token reuse. Lock data is 32 random bytes prepended to
session token itself, to pass authentication hash of this data needs to
be included into token's "appdata" field. If token is created without
REST gateway assistance make sure you use good random data for lock.

### Bearer token flow

It follows the same pattern as /v2/auth/session, except that the contents of
token is different (EACL table). Then this token can be passed into object
operations that accept "NeoFS-Bearer-Token" header. It can be used
independently of session token or along with it.
