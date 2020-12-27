package v1alpha1

import (
	"encoding/json"
	"strconv"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// IngressRouteSpec is a specification for a IngressRouteSpec resource.
type IngressRouteSpec struct {
	Routes      []Route  `json:"routes"`
	EntryPoints []string `json:"entryPoints"`
	TLS         *TLS     `json:"tls,omitempty"`
}

// Route contains the set of routes.
type Route struct {
	Match       string          `json:"match"`
	Kind        string          `json:"kind"`
	Priority    int             `json:"priority"`
	Services    []Service       `json:"services,omitempty"`
	Middlewares []MiddlewareRef `json:"middlewares"`
}

// TLS contains the TLS certificates configuration of the routes.
// To enable Let's Encrypt, use an empty TLS struct,
// e.g. in YAML:
//
//	 tls: {} # inline format
//
//	 tls:
//	   secretName: # block format
type TLS struct {
	// SecretName is the name of the referenced Kubernetes Secret to specify the
	// certificate details.
	SecretName string `json:"secretName"`
	// Options is a reference to a TLSOption, that specifies the parameters of the TLS connection.
	Options *TLSOptionRef `json:"options,omitempty"`
	// Store is a reference to a TLSStore, that specifies the parameters of the TLS store.
	Store        *TLSStoreRef `json:"store,omitempty"`
	CertResolver string       `json:"certResolver,omitempty"`
	Domains      []Domain     `json:"domains,omitempty"`
}

// TLSOptionRef is a ref to the TLSOption resources.
type TLSOptionRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// TLSStoreRef is a ref to the TLSStore resource.
type TLSStoreRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// LoadBalancerSpec can reference either a Kubernetes Service object (a load-balancer of servers),
// or a TraefikService object (a traefik load-balancer of services).
type LoadBalancerSpec struct {
	// Name is a reference to a Kubernetes Service object (for a load-balancer of servers),
	// or to a TraefikService object (service load-balancer, mirroring, etc).
	// The differentiation between the two is specified in the Kind field.
	Name      string  `json:"name"`
	Kind      string  `json:"kind"`
	Namespace string  `json:"namespace"`
	Sticky    *Sticky `json:"sticky,omitempty"`

	// Port and all the fields below are related to a servers load-balancer,
	// and therefore should only be specified when Name references a Kubernetes Service.
	Port               int32               `json:"port"`
	Scheme             string              `json:"scheme,omitempty"`
	Strategy           string              `json:"strategy,omitempty"`
	PassHostHeader     *bool               `json:"passHostHeader,omitempty"`
	ResponseForwarding *ResponseForwarding `json:"responseForwarding,omitempty"`
	ServersTransport   string              `json:"serversTransport,omitempty"`

	// Weight should only be specified when Name references a TraefikService object
	// (and to be precise, one that embeds a Weighted Round Robin).
	Weight *int `json:"weight,omitempty"`
}

// Service defines an upstream to proxy traffic.
type Service struct {
	LoadBalancerSpec
}

// MiddlewareRef is a ref to the Middleware resources.
type MiddlewareRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// IngressRoute is an Ingress CRD specification.
type IngressRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec IngressRouteSpec `json:"spec"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// IngressRouteList is a list of IngressRoutes.
type IngressRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []*IngressRoute `json:"items"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// MiddlewareList is a list of Middleware.
type MiddlewareList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []*Middleware `json:"items"`
}

// Sticky holds the sticky configuration.
type Sticky struct {
	Cookie *Cookie `json:"cookie,omitempty" toml:"cookie,omitempty" yaml:"cookie,omitempty" label:"allowEmpty" file:"allowEmpty"`
}

// ResponseForwarding holds configuration for the forward of the response.
type ResponseForwarding struct {
	FlushInterval string `json:"flushInterval,omitempty" toml:"flushInterval,omitempty" yaml:"flushInterval,omitempty"`
}

// Domain holds a domain name with SANs.
type Domain struct {
	Main string   `description:"Default subject name." json:"main,omitempty" toml:"main,omitempty" yaml:"main,omitempty"`
	SANs []string `description:"Subject alternative names." json:"sans,omitempty" toml:"sans,omitempty" yaml:"sans,omitempty"`
}

// Cookie holds the sticky configuration based on cookie.
type Cookie struct {
	Name     string `json:"name,omitempty" toml:"name,omitempty" yaml:"name,omitempty"`
	Secure   bool   `json:"secure,omitempty" toml:"secure,omitempty" yaml:"secure,omitempty"`
	HTTPOnly bool   `json:"httpOnly,omitempty" toml:"httpOnly,omitempty" yaml:"httpOnly,omitempty"`
	SameSite string `json:"sameSite,omitempty" toml:"sameSite,omitempty" yaml:"sameSite,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Middleware is a specification for a Middleware resource.
type Middleware struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec MiddlewareSpec `json:"spec"`
}

// +k8s:deepcopy-gen=true

// MiddlewareSpec holds the Middleware configuration.
type MiddlewareSpec struct {
	AddPrefix         *AddPrefix            `json:"addPrefix,omitempty"`
	StripPrefix       *StripPrefix          `json:"stripPrefix,omitempty"`
	StripPrefixRegex  *StripPrefixRegex     `json:"stripPrefixRegex,omitempty"`
	ReplacePath       *ReplacePath          `json:"replacePath,omitempty"`
	ReplacePathRegex  *ReplacePathRegex     `json:"replacePathRegex,omitempty"`
	Chain             *Chain                `json:"chain,omitempty"`
	IPWhiteList       *IPWhiteList          `json:"ipWhiteList,omitempty"`
	Headers           *Headers              `json:"headers,omitempty"`
	Errors            *ErrorPage            `json:"errors,omitempty"`
	RateLimit         *RateLimit            `json:"rateLimit,omitempty"`
	RedirectRegex     *RedirectRegex        `json:"redirectRegex,omitempty"`
	RedirectScheme    *RedirectScheme       `json:"redirectScheme,omitempty"`
	BasicAuth         *BasicAuth            `json:"basicAuth,omitempty"`
	DigestAuth        *DigestAuth           `json:"digestAuth,omitempty"`
	ForwardAuth       *ForwardAuth          `json:"forwardAuth,omitempty"`
	InFlightReq       *InFlightReq          `json:"inFlightReq,omitempty"`
	Buffering         *Buffering            `json:"buffering,omitempty"`
	CircuitBreaker    *CircuitBreaker       `json:"circuitBreaker,omitempty"`
	Compress          *Compress             `json:"compress,omitempty"`
	PassTLSClientCert *PassTLSClientCert    `json:"passTLSClientCert,omitempty"`
	Retry             *Retry                `json:"retry,omitempty"`
	ContentType       *ContentType          `json:"contentType,omitempty"`
	Plugin            map[string]PluginConf `json:"plugin,omitempty"`
}

// +k8s:deepcopy-gen=true

// AddPrefix holds the AddPrefix configuration.
type AddPrefix struct {
	Prefix string `json:"prefix,omitempty" toml:"prefix,omitempty" yaml:"prefix,omitempty"`
}

// +k8s:deepcopy-gen=true

// StripPrefix holds the StripPrefix configuration.
type StripPrefix struct {
	Prefixes   []string `json:"prefixes,omitempty" toml:"prefixes,omitempty" yaml:"prefixes,omitempty"`
	ForceSlash bool     `json:"forceSlash,omitempty" toml:"forceSlash,omitempty" yaml:"forceSlash,omitempty"` // Deprecated
}

// +k8s:deepcopy-gen=true

// StripPrefixRegex holds the StripPrefixRegex configuration.
type StripPrefixRegex struct {
	Regex []string `json:"regex,omitempty" toml:"regex,omitempty" yaml:"regex,omitempty"`
}

// +k8s:deepcopy-gen=true

// ReplacePath holds the ReplacePath configuration.
type ReplacePath struct {
	Path string `json:"path,omitempty" toml:"path,omitempty" yaml:"path,omitempty"`
}

// +k8s:deepcopy-gen=true

// ReplacePathRegex holds the ReplacePathRegex configuration.
type ReplacePathRegex struct {
	Regex       string `json:"regex,omitempty" toml:"regex,omitempty" yaml:"regex,omitempty"`
	Replacement string `json:"replacement,omitempty" toml:"replacement,omitempty" yaml:"replacement,omitempty"`
}

// +k8s:deepcopy-gen=true

// Chain holds a chain of middlewares.
type Chain struct {
	Middlewares []MiddlewareRef `json:"middlewares,omitempty"`
}

// +k8s:deepcopy-gen=true

// IPWhiteList holds the ip white list configuration.
type IPWhiteList struct {
	SourceRange []string    `json:"sourceRange,omitempty" toml:"sourceRange,omitempty" yaml:"sourceRange,omitempty"`
	IPStrategy  *IPStrategy `json:"ipStrategy,omitempty" toml:"ipStrategy,omitempty" yaml:"ipStrategy,omitempty"  label:"allowEmpty" file:"allowEmpty"`
}

// +k8s:deepcopy-gen=true

// IPStrategy holds the ip strategy configuration.
type IPStrategy struct {
	Depth       int      `json:"depth,omitempty" toml:"depth,omitempty" yaml:"depth,omitempty" export:"true"`
	ExcludedIPs []string `json:"excludedIPs,omitempty" toml:"excludedIPs,omitempty" yaml:"excludedIPs,omitempty"`
	// TODO(mpl): I think we should make RemoteAddr an explicit field. For one thing, it would yield better documentation.
}

// +k8s:deepcopy-gen=true

// Headers holds the custom header configuration.
type Headers struct {
	CustomRequestHeaders  map[string]string `json:"customRequestHeaders,omitempty" toml:"customRequestHeaders,omitempty" yaml:"customRequestHeaders,omitempty"`
	CustomResponseHeaders map[string]string `json:"customResponseHeaders,omitempty" toml:"customResponseHeaders,omitempty" yaml:"customResponseHeaders,omitempty"`

	// AccessControlAllowCredentials is only valid if true. false is ignored.
	AccessControlAllowCredentials bool `json:"accessControlAllowCredentials,omitempty" toml:"accessControlAllowCredentials,omitempty" yaml:"accessControlAllowCredentials,omitempty"`
	// AccessControlAllowHeaders must be used in response to a preflight request with Access-Control-Request-Headers set.
	AccessControlAllowHeaders []string `json:"accessControlAllowHeaders,omitempty" toml:"accessControlAllowHeaders,omitempty" yaml:"accessControlAllowHeaders,omitempty"`
	// AccessControlAllowMethods must be used in response to a preflight request with Access-Control-Request-Method set.
	AccessControlAllowMethods []string `json:"accessControlAllowMethods,omitempty" toml:"accessControlAllowMethods,omitempty" yaml:"accessControlAllowMethods,omitempty"`
	// AccessControlAllowOrigin Can be "origin-list-or-null" or "*". From (https://www.w3.org/TR/cors/#access-control-allow-origin-response-header)
	AccessControlAllowOrigin string `json:"accessControlAllowOrigin,omitempty" toml:"accessControlAllowOrigin,omitempty" yaml:"accessControlAllowOrigin,omitempty"` // Deprecated
	// AccessControlAllowOriginList is a list of allowable origins. Can also be a wildcard origin "*".
	AccessControlAllowOriginList []string `json:"accessControlAllowOriginList,omitempty" toml:"accessControlAllowOriginList,omitempty" yaml:"accessControlAllowOriginList,omitempty"`
	// AccessControlExposeHeaders sets valid headers for the response.
	AccessControlExposeHeaders []string `json:"accessControlExposeHeaders,omitempty" toml:"accessControlExposeHeaders,omitempty" yaml:"accessControlExposeHeaders,omitempty"`
	// AccessControlMaxAge sets the time that a preflight request may be cached.
	AccessControlMaxAge int64 `json:"accessControlMaxAge,omitempty" toml:"accessControlMaxAge,omitempty" yaml:"accessControlMaxAge,omitempty"`
	// AddVaryHeader controls if the Vary header is automatically added/updated when the AccessControlAllowOrigin is set.
	AddVaryHeader bool `json:"addVaryHeader,omitempty" toml:"addVaryHeader,omitempty" yaml:"addVaryHeader,omitempty"`

	AllowedHosts            []string          `json:"allowedHosts,omitempty" toml:"allowedHosts,omitempty" yaml:"allowedHosts,omitempty"`
	HostsProxyHeaders       []string          `json:"hostsProxyHeaders,omitempty" toml:"hostsProxyHeaders,omitempty" yaml:"hostsProxyHeaders,omitempty"`
	SSLRedirect             bool              `json:"sslRedirect,omitempty" toml:"sslRedirect,omitempty" yaml:"sslRedirect,omitempty"`
	SSLTemporaryRedirect    bool              `json:"sslTemporaryRedirect,omitempty" toml:"sslTemporaryRedirect,omitempty" yaml:"sslTemporaryRedirect,omitempty"`
	SSLHost                 string            `json:"sslHost,omitempty" toml:"sslHost,omitempty" yaml:"sslHost,omitempty"`
	SSLProxyHeaders         map[string]string `json:"sslProxyHeaders,omitempty" toml:"sslProxyHeaders,omitempty" yaml:"sslProxyHeaders,omitempty"`
	SSLForceHost            bool              `json:"sslForceHost,omitempty" toml:"sslForceHost,omitempty" yaml:"sslForceHost,omitempty"`
	STSSeconds              int64             `json:"stsSeconds,omitempty" toml:"stsSeconds,omitempty" yaml:"stsSeconds,omitempty"`
	STSIncludeSubdomains    bool              `json:"stsIncludeSubdomains,omitempty" toml:"stsIncludeSubdomains,omitempty" yaml:"stsIncludeSubdomains,omitempty"`
	STSPreload              bool              `json:"stsPreload,omitempty" toml:"stsPreload,omitempty" yaml:"stsPreload,omitempty"`
	ForceSTSHeader          bool              `json:"forceSTSHeader,omitempty" toml:"forceSTSHeader,omitempty" yaml:"forceSTSHeader,omitempty"`
	FrameDeny               bool              `json:"frameDeny,omitempty" toml:"frameDeny,omitempty" yaml:"frameDeny,omitempty"`
	CustomFrameOptionsValue string            `json:"customFrameOptionsValue,omitempty" toml:"customFrameOptionsValue,omitempty" yaml:"customFrameOptionsValue,omitempty"`
	ContentTypeNosniff      bool              `json:"contentTypeNosniff,omitempty" toml:"contentTypeNosniff,omitempty" yaml:"contentTypeNosniff,omitempty"`
	BrowserXSSFilter        bool              `json:"browserXssFilter,omitempty" toml:"browserXssFilter,omitempty" yaml:"browserXssFilter,omitempty"`
	CustomBrowserXSSValue   string            `json:"customBrowserXSSValue,omitempty" toml:"customBrowserXSSValue,omitempty" yaml:"customBrowserXSSValue,omitempty"`
	ContentSecurityPolicy   string            `json:"contentSecurityPolicy,omitempty" toml:"contentSecurityPolicy,omitempty" yaml:"contentSecurityPolicy,omitempty"`
	PublicKey               string            `json:"publicKey,omitempty" toml:"publicKey,omitempty" yaml:"publicKey,omitempty"`
	ReferrerPolicy          string            `json:"referrerPolicy,omitempty" toml:"referrerPolicy,omitempty" yaml:"referrerPolicy,omitempty"`
	FeaturePolicy           string            `json:"featurePolicy,omitempty" toml:"featurePolicy,omitempty" yaml:"featurePolicy,omitempty"`
	IsDevelopment           bool              `json:"isDevelopment,omitempty" toml:"isDevelopment,omitempty" yaml:"isDevelopment,omitempty"`
}

// +k8s:deepcopy-gen=true

// ErrorPage holds the custom error page configuration.
type ErrorPage struct {
	Status  []string `json:"status,omitempty"`
	Service Service  `json:"service,omitempty"`
	Query   string   `json:"query,omitempty"`
}

// +k8s:deepcopy-gen=true

// RateLimit holds the rate limiting configuration for a given router.
type RateLimit struct {
	// Average is the maximum rate, by default in requests/s, allowed for the given source.
	// It defaults to 0, which means no rate limiting.
	// The rate is actually defined by dividing Average by Period. So for a rate below 1req/s,
	// one needs to define a Period larger than a second.
	Average int64 `json:"average,omitempty" toml:"average,omitempty" yaml:"average,omitempty"`

	// Period, in combination with Average, defines the actual maximum rate, such as:
	// r = Average / Period. It defaults to a second.
	Period Duration `json:"period,omitempty" toml:"period,omitempty" yaml:"period,omitempty"`

	// Burst is the maximum number of requests allowed to arrive in the same arbitrarily small period of time.
	// It defaults to 1.
	Burst int64 `json:"burst,omitempty" toml:"burst,omitempty" yaml:"burst,omitempty"`

	SourceCriterion *SourceCriterion `json:"sourceCriterion,omitempty" toml:"sourceCriterion,omitempty" yaml:"sourceCriterion,omitempty"`
}

// +k8s:deepcopy-gen=true

// SourceCriterion defines what criterion is used to group requests as originating from a common source.
// If none are set, the default is to use the request's remote address field.
// All fields are mutually exclusive.
type SourceCriterion struct {
	IPStrategy        *IPStrategy `json:"ipStrategy,omitempty" toml:"ipStrategy,omitempty" yaml:"ipStrategy,omitempty"`
	RequestHeaderName string      `json:"requestHeaderName,omitempty" toml:"requestHeaderName,omitempty" yaml:"requestHeaderName,omitempty"`
	RequestHost       bool        `json:"requestHost,omitempty" toml:"requestHost,omitempty" yaml:"requestHost,omitempty"`
}

// +k8s:deepcopy-gen=true

// RedirectRegex holds the redirection configuration.
type RedirectRegex struct {
	Regex       string `json:"regex,omitempty" toml:"regex,omitempty" yaml:"regex,omitempty"`
	Replacement string `json:"replacement,omitempty" toml:"replacement,omitempty" yaml:"replacement,omitempty"`
	Permanent   bool   `json:"permanent,omitempty" toml:"permanent,omitempty" yaml:"permanent,omitempty"`
}

// +k8s:deepcopy-gen=true

// RedirectScheme holds the scheme redirection configuration.
type RedirectScheme struct {
	Scheme    string `json:"scheme,omitempty" toml:"scheme,omitempty" yaml:"scheme,omitempty"`
	Port      string `json:"port,omitempty" toml:"port,omitempty" yaml:"port,omitempty"`
	Permanent bool   `json:"permanent,omitempty" toml:"permanent,omitempty" yaml:"permanent,omitempty"`
}

// +k8s:deepcopy-gen=true

// BasicAuth holds the HTTP basic authentication configuration.
type BasicAuth struct {
	Secret       string `json:"secret,omitempty"`
	Realm        string `json:"realm,omitempty"`
	RemoveHeader bool   `json:"removeHeader,omitempty"`
	HeaderField  string `json:"headerField,omitempty"`
}

// +k8s:deepcopy-gen=true

// DigestAuth holds the Digest HTTP authentication configuration.
type DigestAuth struct {
	Secret       string `json:"secret,omitempty"`
	RemoveHeader bool   `json:"removeHeader,omitempty"`
	Realm        string `json:"realm,omitempty"`
	HeaderField  string `json:"headerField,omitempty"`
}

// +k8s:deepcopy-gen=true

// ForwardAuth holds the http forward authentication configuration.
type ForwardAuth struct {
	Address             string     `json:"address,omitempty"`
	TrustForwardHeader  bool       `json:"trustForwardHeader,omitempty"`
	AuthResponseHeaders []string   `json:"authResponseHeaders,omitempty"`
	AuthRequestHeaders  []string   `json:"authRequestHeaders,omitempty"`
	TLS                 *ClientTLS `json:"tls,omitempty"`
}

// ClientTLS holds TLS specific configurations as client.
type ClientTLS struct {
	CASecret           string `json:"caSecret,omitempty"`
	CAOptional         bool   `json:"caOptional,omitempty"`
	CertSecret         string `json:"certSecret,omitempty"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify,omitempty"`
}

// +k8s:deepcopy-gen=true

// InFlightReq limits the number of requests being processed and served concurrently.
type InFlightReq struct {
	Amount          int64            `json:"amount,omitempty" toml:"amount,omitempty" yaml:"amount,omitempty"`
	SourceCriterion *SourceCriterion `json:"sourceCriterion,omitempty" toml:"sourceCriterion,omitempty" yaml:"sourceCriterion,omitempty"`
}

// +k8s:deepcopy-gen=true

// Buffering holds the request/response buffering configuration.
type Buffering struct {
	MaxRequestBodyBytes  int64  `json:"maxRequestBodyBytes,omitempty" toml:"maxRequestBodyBytes,omitempty" yaml:"maxRequestBodyBytes,omitempty"`
	MemRequestBodyBytes  int64  `json:"memRequestBodyBytes,omitempty" toml:"memRequestBodyBytes,omitempty" yaml:"memRequestBodyBytes,omitempty"`
	MaxResponseBodyBytes int64  `json:"maxResponseBodyBytes,omitempty" toml:"maxResponseBodyBytes,omitempty" yaml:"maxResponseBodyBytes,omitempty"`
	MemResponseBodyBytes int64  `json:"memResponseBodyBytes,omitempty" toml:"memResponseBodyBytes,omitempty" yaml:"memResponseBodyBytes,omitempty"`
	RetryExpression      string `json:"retryExpression,omitempty" toml:"retryExpression,omitempty" yaml:"retryExpression,omitempty"`
}

// +k8s:deepcopy-gen=true

// CircuitBreaker holds the circuit breaker configuration.
type CircuitBreaker struct {
	Expression string `json:"expression,omitempty" toml:"expression,omitempty" yaml:"expression,omitempty"`
}

// +k8s:deepcopy-gen=true

// Compress holds the compress configuration.
type Compress struct {
	ExcludedContentTypes []string `json:"excludedContentTypes,omitempty" toml:"excludedContentTypes,omitempty" yaml:"excludedContentTypes,omitempty" export:"true"`
}

// +k8s:deepcopy-gen=true

// PassTLSClientCert holds the TLS client cert headers configuration.
type PassTLSClientCert struct {
	PEM  bool                      `json:"pem,omitempty" toml:"pem,omitempty" yaml:"pem,omitempty"`
	Info *TLSClientCertificateInfo `json:"info,omitempty" toml:"info,omitempty" yaml:"info,omitempty"`
}

// +k8s:deepcopy-gen=true

// TLSClientCertificateInfo holds the client TLS certificate info configuration.
type TLSClientCertificateInfo struct {
	NotAfter     bool                        `json:"notAfter,omitempty" toml:"notAfter,omitempty" yaml:"notAfter,omitempty"`
	NotBefore    bool                        `json:"notBefore,omitempty" toml:"notBefore,omitempty" yaml:"notBefore,omitempty"`
	Sans         bool                        `json:"sans,omitempty" toml:"sans,omitempty" yaml:"sans,omitempty"`
	Subject      *TLSCLientCertificateDNInfo `json:"subject,omitempty" toml:"subject,omitempty" yaml:"subject,omitempty"`
	Issuer       *TLSCLientCertificateDNInfo `json:"issuer,omitempty" toml:"issuer,omitempty" yaml:"issuer,omitempty"`
	SerialNumber bool                        `json:"serialNumber,omitempty" toml:"serialNumber,omitempty" yaml:"serialNumber,omitempty"`
}

// +k8s:deepcopy-gen=true

// TLSCLientCertificateDNInfo holds the client TLS certificate distinguished name info configuration
// cf https://tools.ietf.org/html/rfc3739
type TLSCLientCertificateDNInfo struct {
	Country         bool `json:"country,omitempty" toml:"country,omitempty" yaml:"country,omitempty"`
	Province        bool `json:"province,omitempty" toml:"province,omitempty" yaml:"province,omitempty"`
	Locality        bool `json:"locality,omitempty" toml:"locality,omitempty" yaml:"locality,omitempty"`
	Organization    bool `json:"organization,omitempty" toml:"organization,omitempty" yaml:"organization,omitempty"`
	CommonName      bool `json:"commonName,omitempty" toml:"commonName,omitempty" yaml:"commonName,omitempty"`
	SerialNumber    bool `json:"serialNumber,omitempty" toml:"serialNumber,omitempty" yaml:"serialNumber,omitempty"`
	DomainComponent bool `json:"domainComponent,omitempty" toml:"domainComponent,omitempty" yaml:"domainComponent,omitempty"`
}

// +k8s:deepcopy-gen=true

// Retry holds the retry configuration.
type Retry struct {
	Attempts int `json:"attempts,omitempty" toml:"attempts,omitempty" yaml:"attempts,omitempty" export:"true"`
}

// +k8s:deepcopy-gen=true

// ContentType middleware - or rather its unique `autoDetect` option -
// specifies whether to let the `Content-Type` header,
// if it has not been set by the backend,
// be automatically set to a value derived from the contents of the response.
// As a proxy, the default behavior should be to leave the header alone,
// regardless of what the backend did with it.
// However, the historic default was to always auto-detect and set the header if it was nil,
// and it is going to be kept that way in order to support users currently relying on it.
// This middleware exists to enable the correct behavior until at least the default one can be changed in a future version.
type ContentType struct {
	AutoDetect bool `json:"autoDetect,omitempty" toml:"autoDetect,omitempty" yaml:"autoDetect,omitempty"`
}

// +k8s:deepcopy-gen=false

// PluginConf holds the plugin configuration.
type PluginConf map[string]interface{}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PluginConf) DeepCopyInto(out *PluginConf) {
	if in == nil {
		*out = nil
	} else {
		*out = runtime.DeepCopyJSON(*in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PluginConf.
func (in *PluginConf) DeepCopy() *PluginConf {
	if in == nil {
		return nil
	}
	out := new(PluginConf)
	in.DeepCopyInto(out)
	return out
}

// Duration is a custom type suitable for parsing duration values.
// It supports `time.ParseDuration`-compatible values and suffix-less digits; in
// the latter case, seconds are assumed.
type Duration time.Duration

// Set sets the duration from the given string value.
func (d *Duration) Set(s string) error {
	if v, err := strconv.ParseInt(s, 10, 64); err == nil {
		*d = Duration(time.Duration(v) * time.Second)
		return nil
	}

	v, err := time.ParseDuration(s)
	*d = Duration(v)
	return err
}

// String returns a string representation of the duration value.
func (d Duration) String() string { return (time.Duration)(d).String() }

// MarshalText serialize the given duration value into a text.
func (d Duration) MarshalText() ([]byte, error) {
	return []byte(d.String()), nil
}

// UnmarshalText deserializes the given text into a duration value.
// It is meant to support TOML decoding of durations.
func (d *Duration) UnmarshalText(text []byte) error {
	return d.Set(string(text))
}

// MarshalJSON serializes the given duration value.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d))
}

// UnmarshalJSON deserializes the given text into a duration value.
func (d *Duration) UnmarshalJSON(text []byte) error {
	if v, err := strconv.ParseInt(string(text), 10, 64); err == nil {
		*d = Duration(time.Duration(v))
		return nil
	}

	// We use json unmarshal on value because we have the quoted version
	var value string
	err := json.Unmarshal(text, &value)
	if err != nil {
		return err
	}
	v, err := time.ParseDuration(value)
	*d = Duration(v)
	return err
}
