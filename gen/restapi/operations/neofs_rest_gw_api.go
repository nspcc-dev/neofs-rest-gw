// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/loads"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/runtime/security"
	"github.com/go-openapi/spec"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"

	"github.com/nspcc-dev/neofs-rest-gw/gen/models"
)

// NewNeofsRestGwAPI creates a new NeofsRestGw instance
func NewNeofsRestGwAPI(spec *loads.Document) *NeofsRestGwAPI {
	return &NeofsRestGwAPI{
		handlers:            make(map[string]map[string]http.Handler),
		formats:             strfmt.Default,
		defaultConsumes:     "application/json",
		defaultProduces:     "application/json",
		customConsumers:     make(map[string]runtime.Consumer),
		customProducers:     make(map[string]runtime.Producer),
		PreServerShutdown:   func() {},
		ServerShutdown:      func() {},
		spec:                spec,
		useSwaggerUI:        false,
		ServeError:          errors.ServeError,
		BasicAuthenticator:  security.BasicAuth,
		APIKeyAuthenticator: security.APIKeyAuth,
		BearerAuthenticator: security.BearerAuth,

		JSONConsumer: runtime.JSONConsumer(),

		JSONProducer: runtime.JSONProducer(),

		AuthHandler: AuthHandlerFunc(func(params AuthParams) middleware.Responder {
			return middleware.NotImplemented("operation Auth has not yet been implemented")
		}),
		DeleteContainerHandler: DeleteContainerHandlerFunc(func(params DeleteContainerParams, principal *models.Principal) middleware.Responder {
			return middleware.NotImplemented("operation DeleteContainer has not yet been implemented")
		}),
		DeleteObjectHandler: DeleteObjectHandlerFunc(func(params DeleteObjectParams, principal *models.Principal) middleware.Responder {
			return middleware.NotImplemented("operation DeleteObject has not yet been implemented")
		}),
		DeleteStorageGroupHandler: DeleteStorageGroupHandlerFunc(func(params DeleteStorageGroupParams, principal *models.Principal) middleware.Responder {
			return middleware.NotImplemented("operation DeleteStorageGroup has not yet been implemented")
		}),
		GetBalanceHandler: GetBalanceHandlerFunc(func(params GetBalanceParams) middleware.Responder {
			return middleware.NotImplemented("operation GetBalance has not yet been implemented")
		}),
		GetContainerHandler: GetContainerHandlerFunc(func(params GetContainerParams) middleware.Responder {
			return middleware.NotImplemented("operation GetContainer has not yet been implemented")
		}),
		GetContainerEACLHandler: GetContainerEACLHandlerFunc(func(params GetContainerEACLParams) middleware.Responder {
			return middleware.NotImplemented("operation GetContainerEACL has not yet been implemented")
		}),
		GetObjectInfoHandler: GetObjectInfoHandlerFunc(func(params GetObjectInfoParams, principal *models.Principal) middleware.Responder {
			return middleware.NotImplemented("operation GetObjectInfo has not yet been implemented")
		}),
		GetStorageGroupHandler: GetStorageGroupHandlerFunc(func(params GetStorageGroupParams, principal *models.Principal) middleware.Responder {
			return middleware.NotImplemented("operation GetStorageGroup has not yet been implemented")
		}),
		ListContainersHandler: ListContainersHandlerFunc(func(params ListContainersParams) middleware.Responder {
			return middleware.NotImplemented("operation ListContainers has not yet been implemented")
		}),
		ListStorageGroupsHandler: ListStorageGroupsHandlerFunc(func(params ListStorageGroupsParams, principal *models.Principal) middleware.Responder {
			return middleware.NotImplemented("operation ListStorageGroups has not yet been implemented")
		}),
		PutContainerHandler: PutContainerHandlerFunc(func(params PutContainerParams, principal *models.Principal) middleware.Responder {
			return middleware.NotImplemented("operation PutContainer has not yet been implemented")
		}),
		PutContainerEACLHandler: PutContainerEACLHandlerFunc(func(params PutContainerEACLParams, principal *models.Principal) middleware.Responder {
			return middleware.NotImplemented("operation PutContainerEACL has not yet been implemented")
		}),
		PutObjectHandler: PutObjectHandlerFunc(func(params PutObjectParams, principal *models.Principal) middleware.Responder {
			return middleware.NotImplemented("operation PutObject has not yet been implemented")
		}),
		PutStorageGroupHandler: PutStorageGroupHandlerFunc(func(params PutStorageGroupParams, principal *models.Principal) middleware.Responder {
			return middleware.NotImplemented("operation PutStorageGroup has not yet been implemented")
		}),
		SearchObjectsHandler: SearchObjectsHandlerFunc(func(params SearchObjectsParams, principal *models.Principal) middleware.Responder {
			return middleware.NotImplemented("operation SearchObjects has not yet been implemented")
		}),

		// Applies when the "Authorization" header is set
		BearerAuthAuth: func(token string) (*models.Principal, error) {
			return nil, errors.NotImplemented("api key auth (BearerAuth) Authorization from header param [Authorization] has not yet been implemented")
		},
		// default authorizer is authorized meaning no requests are blocked
		APIAuthorizer: security.Authorized(),
	}
}

/*NeofsRestGwAPI REST API for native integration with NeoFS. */
type NeofsRestGwAPI struct {
	spec            *loads.Document
	context         *middleware.Context
	handlers        map[string]map[string]http.Handler
	formats         strfmt.Registry
	customConsumers map[string]runtime.Consumer
	customProducers map[string]runtime.Producer
	defaultConsumes string
	defaultProduces string
	Middleware      func(middleware.Builder) http.Handler
	useSwaggerUI    bool

	// BasicAuthenticator generates a runtime.Authenticator from the supplied basic auth function.
	// It has a default implementation in the security package, however you can replace it for your particular usage.
	BasicAuthenticator func(security.UserPassAuthentication) runtime.Authenticator

	// APIKeyAuthenticator generates a runtime.Authenticator from the supplied token auth function.
	// It has a default implementation in the security package, however you can replace it for your particular usage.
	APIKeyAuthenticator func(string, string, security.TokenAuthentication) runtime.Authenticator

	// BearerAuthenticator generates a runtime.Authenticator from the supplied bearer token auth function.
	// It has a default implementation in the security package, however you can replace it for your particular usage.
	BearerAuthenticator func(string, security.ScopedTokenAuthentication) runtime.Authenticator

	// JSONConsumer registers a consumer for the following mime types:
	//   - application/json
	JSONConsumer runtime.Consumer

	// JSONProducer registers a producer for the following mime types:
	//   - application/json
	JSONProducer runtime.Producer

	// BearerAuthAuth registers a function that takes a token and returns a principal
	// it performs authentication based on an api key Authorization provided in the header
	BearerAuthAuth func(string) (*models.Principal, error)

	// APIAuthorizer provides access control (ACL/RBAC/ABAC) by providing access to the request and authenticated principal
	APIAuthorizer runtime.Authorizer

	// AuthHandler sets the operation handler for the auth operation
	AuthHandler AuthHandler
	// DeleteContainerHandler sets the operation handler for the delete container operation
	DeleteContainerHandler DeleteContainerHandler
	// DeleteObjectHandler sets the operation handler for the delete object operation
	DeleteObjectHandler DeleteObjectHandler
	// DeleteStorageGroupHandler sets the operation handler for the delete storage group operation
	DeleteStorageGroupHandler DeleteStorageGroupHandler
	// GetBalanceHandler sets the operation handler for the get balance operation
	GetBalanceHandler GetBalanceHandler
	// GetContainerHandler sets the operation handler for the get container operation
	GetContainerHandler GetContainerHandler
	// GetContainerEACLHandler sets the operation handler for the get container e ACL operation
	GetContainerEACLHandler GetContainerEACLHandler
	// GetObjectInfoHandler sets the operation handler for the get object info operation
	GetObjectInfoHandler GetObjectInfoHandler
	// GetStorageGroupHandler sets the operation handler for the get storage group operation
	GetStorageGroupHandler GetStorageGroupHandler
	// ListContainersHandler sets the operation handler for the list containers operation
	ListContainersHandler ListContainersHandler
	// ListStorageGroupsHandler sets the operation handler for the list storage groups operation
	ListStorageGroupsHandler ListStorageGroupsHandler
	// PutContainerHandler sets the operation handler for the put container operation
	PutContainerHandler PutContainerHandler
	// PutContainerEACLHandler sets the operation handler for the put container e ACL operation
	PutContainerEACLHandler PutContainerEACLHandler
	// PutObjectHandler sets the operation handler for the put object operation
	PutObjectHandler PutObjectHandler
	// PutStorageGroupHandler sets the operation handler for the put storage group operation
	PutStorageGroupHandler PutStorageGroupHandler
	// SearchObjectsHandler sets the operation handler for the search objects operation
	SearchObjectsHandler SearchObjectsHandler

	// ServeError is called when an error is received, there is a default handler
	// but you can set your own with this
	ServeError func(http.ResponseWriter, *http.Request, error)

	// PreServerShutdown is called before the HTTP(S) server is shutdown
	// This allows for custom functions to get executed before the HTTP(S) server stops accepting traffic
	PreServerShutdown func()

	// ServerShutdown is called when the HTTP(S) server is shut down and done
	// handling all active connections and does not accept connections any more
	ServerShutdown func()

	// Custom command line argument groups with their descriptions
	CommandLineOptionsGroups []swag.CommandLineOptionsGroup

	// User defined logger function.
	Logger func(string, ...interface{})
}

// UseRedoc for documentation at /docs
func (o *NeofsRestGwAPI) UseRedoc() {
	o.useSwaggerUI = false
}

// UseSwaggerUI for documentation at /docs
func (o *NeofsRestGwAPI) UseSwaggerUI() {
	o.useSwaggerUI = true
}

// SetDefaultProduces sets the default produces media type
func (o *NeofsRestGwAPI) SetDefaultProduces(mediaType string) {
	o.defaultProduces = mediaType
}

// SetDefaultConsumes returns the default consumes media type
func (o *NeofsRestGwAPI) SetDefaultConsumes(mediaType string) {
	o.defaultConsumes = mediaType
}

// SetSpec sets a spec that will be served for the clients.
func (o *NeofsRestGwAPI) SetSpec(spec *loads.Document) {
	o.spec = spec
}

// DefaultProduces returns the default produces media type
func (o *NeofsRestGwAPI) DefaultProduces() string {
	return o.defaultProduces
}

// DefaultConsumes returns the default consumes media type
func (o *NeofsRestGwAPI) DefaultConsumes() string {
	return o.defaultConsumes
}

// Formats returns the registered string formats
func (o *NeofsRestGwAPI) Formats() strfmt.Registry {
	return o.formats
}

// RegisterFormat registers a custom format validator
func (o *NeofsRestGwAPI) RegisterFormat(name string, format strfmt.Format, validator strfmt.Validator) {
	o.formats.Add(name, format, validator)
}

// Validate validates the registrations in the NeofsRestGwAPI
func (o *NeofsRestGwAPI) Validate() error {
	var unregistered []string

	if o.JSONConsumer == nil {
		unregistered = append(unregistered, "JSONConsumer")
	}

	if o.JSONProducer == nil {
		unregistered = append(unregistered, "JSONProducer")
	}

	if o.BearerAuthAuth == nil {
		unregistered = append(unregistered, "AuthorizationAuth")
	}

	if o.AuthHandler == nil {
		unregistered = append(unregistered, "AuthHandler")
	}
	if o.DeleteContainerHandler == nil {
		unregistered = append(unregistered, "DeleteContainerHandler")
	}
	if o.DeleteObjectHandler == nil {
		unregistered = append(unregistered, "DeleteObjectHandler")
	}
	if o.DeleteStorageGroupHandler == nil {
		unregistered = append(unregistered, "DeleteStorageGroupHandler")
	}
	if o.GetBalanceHandler == nil {
		unregistered = append(unregistered, "GetBalanceHandler")
	}
	if o.GetContainerHandler == nil {
		unregistered = append(unregistered, "GetContainerHandler")
	}
	if o.GetContainerEACLHandler == nil {
		unregistered = append(unregistered, "GetContainerEACLHandler")
	}
	if o.GetObjectInfoHandler == nil {
		unregistered = append(unregistered, "GetObjectInfoHandler")
	}
	if o.GetStorageGroupHandler == nil {
		unregistered = append(unregistered, "GetStorageGroupHandler")
	}
	if o.ListContainersHandler == nil {
		unregistered = append(unregistered, "ListContainersHandler")
	}
	if o.ListStorageGroupsHandler == nil {
		unregistered = append(unregistered, "ListStorageGroupsHandler")
	}
	if o.PutContainerHandler == nil {
		unregistered = append(unregistered, "PutContainerHandler")
	}
	if o.PutContainerEACLHandler == nil {
		unregistered = append(unregistered, "PutContainerEACLHandler")
	}
	if o.PutObjectHandler == nil {
		unregistered = append(unregistered, "PutObjectHandler")
	}
	if o.PutStorageGroupHandler == nil {
		unregistered = append(unregistered, "PutStorageGroupHandler")
	}
	if o.SearchObjectsHandler == nil {
		unregistered = append(unregistered, "SearchObjectsHandler")
	}

	if len(unregistered) > 0 {
		return fmt.Errorf("missing registration: %s", strings.Join(unregistered, ", "))
	}

	return nil
}

// ServeErrorFor gets a error handler for a given operation id
func (o *NeofsRestGwAPI) ServeErrorFor(operationID string) func(http.ResponseWriter, *http.Request, error) {
	return o.ServeError
}

// AuthenticatorsFor gets the authenticators for the specified security schemes
func (o *NeofsRestGwAPI) AuthenticatorsFor(schemes map[string]spec.SecurityScheme) map[string]runtime.Authenticator {
	result := make(map[string]runtime.Authenticator)
	for name := range schemes {
		switch name {
		case "BearerAuth":
			scheme := schemes[name]
			result[name] = o.APIKeyAuthenticator(scheme.Name, scheme.In, func(token string) (interface{}, error) {
				return o.BearerAuthAuth(token)
			})

		}
	}
	return result
}

// Authorizer returns the registered authorizer
func (o *NeofsRestGwAPI) Authorizer() runtime.Authorizer {
	return o.APIAuthorizer
}

// ConsumersFor gets the consumers for the specified media types.
// MIME type parameters are ignored here.
func (o *NeofsRestGwAPI) ConsumersFor(mediaTypes []string) map[string]runtime.Consumer {
	result := make(map[string]runtime.Consumer, len(mediaTypes))
	for _, mt := range mediaTypes {
		switch mt {
		case "application/json":
			result["application/json"] = o.JSONConsumer
		}

		if c, ok := o.customConsumers[mt]; ok {
			result[mt] = c
		}
	}
	return result
}

// ProducersFor gets the producers for the specified media types.
// MIME type parameters are ignored here.
func (o *NeofsRestGwAPI) ProducersFor(mediaTypes []string) map[string]runtime.Producer {
	result := make(map[string]runtime.Producer, len(mediaTypes))
	for _, mt := range mediaTypes {
		switch mt {
		case "application/json":
			result["application/json"] = o.JSONProducer
		}

		if p, ok := o.customProducers[mt]; ok {
			result[mt] = p
		}
	}
	return result
}

// HandlerFor gets a http.Handler for the provided operation method and path
func (o *NeofsRestGwAPI) HandlerFor(method, path string) (http.Handler, bool) {
	if o.handlers == nil {
		return nil, false
	}
	um := strings.ToUpper(method)
	if _, ok := o.handlers[um]; !ok {
		return nil, false
	}
	if path == "/" {
		path = ""
	}
	h, ok := o.handlers[um][path]
	return h, ok
}

// Context returns the middleware context for the neofs rest gw API
func (o *NeofsRestGwAPI) Context() *middleware.Context {
	if o.context == nil {
		o.context = middleware.NewRoutableContext(o.spec, o, nil)
	}

	return o.context
}

func (o *NeofsRestGwAPI) initHandlerCache() {
	o.Context() // don't care about the result, just that the initialization happened
	if o.handlers == nil {
		o.handlers = make(map[string]map[string]http.Handler)
	}

	if o.handlers["POST"] == nil {
		o.handlers["POST"] = make(map[string]http.Handler)
	}
	o.handlers["POST"]["/auth"] = NewAuth(o.context, o.AuthHandler)
	if o.handlers["DELETE"] == nil {
		o.handlers["DELETE"] = make(map[string]http.Handler)
	}
	o.handlers["DELETE"]["/containers/{containerId}"] = NewDeleteContainer(o.context, o.DeleteContainerHandler)
	if o.handlers["DELETE"] == nil {
		o.handlers["DELETE"] = make(map[string]http.Handler)
	}
	o.handlers["DELETE"]["/objects/{containerId}/{objectId}"] = NewDeleteObject(o.context, o.DeleteObjectHandler)
	if o.handlers["DELETE"] == nil {
		o.handlers["DELETE"] = make(map[string]http.Handler)
	}
	o.handlers["DELETE"]["/containers/{containerId}/storagegroups/{storageGroupId}"] = NewDeleteStorageGroup(o.context, o.DeleteStorageGroupHandler)
	if o.handlers["GET"] == nil {
		o.handlers["GET"] = make(map[string]http.Handler)
	}
	o.handlers["GET"]["/accounting/balance/{address}"] = NewGetBalance(o.context, o.GetBalanceHandler)
	if o.handlers["GET"] == nil {
		o.handlers["GET"] = make(map[string]http.Handler)
	}
	o.handlers["GET"]["/containers/{containerId}"] = NewGetContainer(o.context, o.GetContainerHandler)
	if o.handlers["GET"] == nil {
		o.handlers["GET"] = make(map[string]http.Handler)
	}
	o.handlers["GET"]["/containers/{containerId}/eacl"] = NewGetContainerEACL(o.context, o.GetContainerEACLHandler)
	if o.handlers["GET"] == nil {
		o.handlers["GET"] = make(map[string]http.Handler)
	}
	o.handlers["GET"]["/objects/{containerId}/{objectId}"] = NewGetObjectInfo(o.context, o.GetObjectInfoHandler)
	if o.handlers["GET"] == nil {
		o.handlers["GET"] = make(map[string]http.Handler)
	}
	o.handlers["GET"]["/containers/{containerId}/storagegroups/{storageGroupId}"] = NewGetStorageGroup(o.context, o.GetStorageGroupHandler)
	if o.handlers["GET"] == nil {
		o.handlers["GET"] = make(map[string]http.Handler)
	}
	o.handlers["GET"]["/containers"] = NewListContainers(o.context, o.ListContainersHandler)
	if o.handlers["GET"] == nil {
		o.handlers["GET"] = make(map[string]http.Handler)
	}
	o.handlers["GET"]["/containers/{containerId}/storagegroups"] = NewListStorageGroups(o.context, o.ListStorageGroupsHandler)
	if o.handlers["PUT"] == nil {
		o.handlers["PUT"] = make(map[string]http.Handler)
	}
	o.handlers["PUT"]["/containers"] = NewPutContainer(o.context, o.PutContainerHandler)
	if o.handlers["PUT"] == nil {
		o.handlers["PUT"] = make(map[string]http.Handler)
	}
	o.handlers["PUT"]["/containers/{containerId}/eacl"] = NewPutContainerEACL(o.context, o.PutContainerEACLHandler)
	if o.handlers["PUT"] == nil {
		o.handlers["PUT"] = make(map[string]http.Handler)
	}
	o.handlers["PUT"]["/objects"] = NewPutObject(o.context, o.PutObjectHandler)
	if o.handlers["PUT"] == nil {
		o.handlers["PUT"] = make(map[string]http.Handler)
	}
	o.handlers["PUT"]["/containers/{containerId}/storagegroups"] = NewPutStorageGroup(o.context, o.PutStorageGroupHandler)
	if o.handlers["POST"] == nil {
		o.handlers["POST"] = make(map[string]http.Handler)
	}
	o.handlers["POST"]["/objects/{containerId}/search"] = NewSearchObjects(o.context, o.SearchObjectsHandler)
}

// Serve creates a http handler to serve the API over HTTP
// can be used directly in http.ListenAndServe(":8000", api.Serve(nil))
func (o *NeofsRestGwAPI) Serve(builder middleware.Builder) http.Handler {
	o.Init()

	if o.Middleware != nil {
		return o.Middleware(builder)
	}
	if o.useSwaggerUI {
		return o.context.APIHandlerSwaggerUI(builder)
	}
	return o.context.APIHandler(builder)
}

// Init allows you to just initialize the handler cache, you can then recompose the middleware as you see fit
func (o *NeofsRestGwAPI) Init() {
	if len(o.handlers) == 0 {
		o.initHandlerCache()
	}
}

// RegisterConsumer allows you to add (or override) a consumer for a media type.
func (o *NeofsRestGwAPI) RegisterConsumer(mediaType string, consumer runtime.Consumer) {
	o.customConsumers[mediaType] = consumer
}

// RegisterProducer allows you to add (or override) a producer for a media type.
func (o *NeofsRestGwAPI) RegisterProducer(mediaType string, producer runtime.Producer) {
	o.customProducers[mediaType] = producer
}

// AddMiddlewareFor adds a http middleware to existing handler
func (o *NeofsRestGwAPI) AddMiddlewareFor(method, path string, builder middleware.Builder) {
	um := strings.ToUpper(method)
	if path == "/" {
		path = ""
	}
	o.Init()
	if h, ok := o.handlers[um][path]; ok {
		o.handlers[method][path] = builder(h)
	}
}
