# Migrating for using new upload and download requests

Starting with the 0.9.0 release of the REST gateway, several new API calls for 
object upload and download are provided. We highly recommend using them instead
of other existing upload/download requests due to their deprecation and 
deletion in the future.

### Upload

POST request to `/objects/{containerId}` for uploading objects. This is quite
similar to `/upload/{containerId}`, but it accepts all custom object attributes
in the new header `X-Attributes`. All attributes, including well-known ones
like "FilePath", "FileName", and "Timestamp", can be passed in a JSON-formatted
key-value map. Thanks to the JSON format of this header, we no longer face
issues with the case-insensitivity of the gateway and the case-sensitivity of
NeoFS. All attributes are passed directly to NeoFS. Additionally, 
`X-Neofs-EXPIRATION*` headers are available to set object expiration. Learn 
more in the Swagger documentation (`/v1/docs`).

Notice that while the `/upload` API required you to create a multipart/form-data
payload, with new API you can just push object payload in the HTTP BODY.
However, whereas previously you always had a file name passed with the form
data, now you need to pass it as an attribute.

Compared to the old `/objects` API you no longer need to serialize object
payload into JSON which is more effective, container ID is passed in the path
and attributes can be added via `X-Attributes`.

Also, please note that the object attribute "Timestamp" can now be filled in
three ways: through the header `X-Attributes`, automatically if
"DefaultTimestamp" is enabled by settings, or in a new third way. The `Date`
header of the upload request is parsed and saved as the object attribute
"Timestamp."

### Download

There are two ways to download objects. The first one, if the object ID is 
known, is a GET request to `/objects/{containerId}/by_id/{objectId}`. Another
approach is searching for an object by attribute with a GET request to
`/objects/{containerId}/by_attribute/{attrKey}/{attrVal}`. In the responses of
both requests, all custom object attributes will be placed in the 
`X-Attributes` header. Additionally, you can send a HEAD request to both paths
to get object information without the object itself.

Compared to the old `/objects/{containerId}/{objectId}` API you now get
payload in HTTP BODY which is easier to integrate for most applications. You
no longer can request a range of an object, if you need it please submit an
issue.
