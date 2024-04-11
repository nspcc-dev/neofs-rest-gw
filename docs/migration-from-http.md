# Migrating from HTTP gateway

Starting with the 0.7.0 release of the REST gateway it provides an API
compatible with the one previously provided by [HTTP gateway](https://github.com/nspcc-dev/neofs-http-gw):
 * `get/$CID/$OID`
 * `get_by_attribute/$CID/$ATTRIBUTE_NAME/$ATTRIBUTE_VALUE`
 * `upload/$CID`

Zip API (`/zip/$CID`) is not provided (it was always disabled on test gateways
and we found no users of it otherwise), please add comments to the [respective
issue](https://github.com/nspcc-dev/neofs-rest-gw/issues/112) if you need it.

The only signficant change in supported APIs is that you need to add a `v1`
prefix to your URLs, so you should use:
 * `v1/get/$CID/$OID`
 * `v1/get_by_attribute/$CID/$ATTRIBUTE_NAME/$ATTRIBUTE_VALUE`
 * `v1/upload/$CID`

The behavior for bearer token and `download=true` argument is the same both
for upload and download. Header/attribute handling is also the same except
that attributes are normalized to their canonical form (see [Go doc](https://pkg.go.dev/net/http#CanonicalHeaderKey))
during upload (previously they were treated as is). There are two attributes
that are treated specially: `FilePath` and `FileName`, these are always passed
to NeoFS as written above (even if it's `fIlEpAtH` in request headers NeoFS
will get `FilePath`). Notice that this API is historic and was never reliable
for headers which are case-insensitive in HTTP (and can be mangled in transit)
and case-sensitive in NeoFS (see the [respective bug](https://github.com/nspcc-dev/neofs-http-gw/issues/255)
as well), if this causes any problems for you please switch to other APIs
provided by the REST gateway (like `/objects`).

The other known difference is that the old HTTP gateway accepted some incorrect
symbols in headers (like "@") which was never intended to happen (it violates
[HTTP specification](https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.6)),
but was purely an implementation specifics. This is no longer allowed, but if
you have any problem with that it just means you should fix your application.

There is a limitation for `$ATTRIBUTE_NAME` and `$ATTRIBUTE_VALUE`. These parameters
should not contain `%` symbol. Using percent symbol [leads to error](https://github.com/nspcc-dev/neofs-rest-gw/issues/195).
