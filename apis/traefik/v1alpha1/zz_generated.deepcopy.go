// +build !ignore_autogenerated

/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by deepcopy-gen. DO NOT EDIT.

package v1alpha1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AddPrefix) DeepCopyInto(out *AddPrefix) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AddPrefix.
func (in *AddPrefix) DeepCopy() *AddPrefix {
	if in == nil {
		return nil
	}
	out := new(AddPrefix)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BasicAuth) DeepCopyInto(out *BasicAuth) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BasicAuth.
func (in *BasicAuth) DeepCopy() *BasicAuth {
	if in == nil {
		return nil
	}
	out := new(BasicAuth)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Buffering) DeepCopyInto(out *Buffering) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Buffering.
func (in *Buffering) DeepCopy() *Buffering {
	if in == nil {
		return nil
	}
	out := new(Buffering)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Chain) DeepCopyInto(out *Chain) {
	*out = *in
	if in.Middlewares != nil {
		in, out := &in.Middlewares, &out.Middlewares
		*out = make([]MiddlewareRef, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Chain.
func (in *Chain) DeepCopy() *Chain {
	if in == nil {
		return nil
	}
	out := new(Chain)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CircuitBreaker) DeepCopyInto(out *CircuitBreaker) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CircuitBreaker.
func (in *CircuitBreaker) DeepCopy() *CircuitBreaker {
	if in == nil {
		return nil
	}
	out := new(CircuitBreaker)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClientTLS) DeepCopyInto(out *ClientTLS) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClientTLS.
func (in *ClientTLS) DeepCopy() *ClientTLS {
	if in == nil {
		return nil
	}
	out := new(ClientTLS)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Compress) DeepCopyInto(out *Compress) {
	*out = *in
	if in.ExcludedContentTypes != nil {
		in, out := &in.ExcludedContentTypes, &out.ExcludedContentTypes
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Compress.
func (in *Compress) DeepCopy() *Compress {
	if in == nil {
		return nil
	}
	out := new(Compress)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ContentType) DeepCopyInto(out *ContentType) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ContentType.
func (in *ContentType) DeepCopy() *ContentType {
	if in == nil {
		return nil
	}
	out := new(ContentType)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Cookie) DeepCopyInto(out *Cookie) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Cookie.
func (in *Cookie) DeepCopy() *Cookie {
	if in == nil {
		return nil
	}
	out := new(Cookie)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DigestAuth) DeepCopyInto(out *DigestAuth) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DigestAuth.
func (in *DigestAuth) DeepCopy() *DigestAuth {
	if in == nil {
		return nil
	}
	out := new(DigestAuth)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Domain) DeepCopyInto(out *Domain) {
	*out = *in
	if in.SANs != nil {
		in, out := &in.SANs, &out.SANs
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Domain.
func (in *Domain) DeepCopy() *Domain {
	if in == nil {
		return nil
	}
	out := new(Domain)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ErrorPage) DeepCopyInto(out *ErrorPage) {
	*out = *in
	if in.Status != nil {
		in, out := &in.Status, &out.Status
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	in.Service.DeepCopyInto(&out.Service)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ErrorPage.
func (in *ErrorPage) DeepCopy() *ErrorPage {
	if in == nil {
		return nil
	}
	out := new(ErrorPage)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ForwardAuth) DeepCopyInto(out *ForwardAuth) {
	*out = *in
	if in.AuthResponseHeaders != nil {
		in, out := &in.AuthResponseHeaders, &out.AuthResponseHeaders
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.AuthRequestHeaders != nil {
		in, out := &in.AuthRequestHeaders, &out.AuthRequestHeaders
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.TLS != nil {
		in, out := &in.TLS, &out.TLS
		*out = new(ClientTLS)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ForwardAuth.
func (in *ForwardAuth) DeepCopy() *ForwardAuth {
	if in == nil {
		return nil
	}
	out := new(ForwardAuth)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Headers) DeepCopyInto(out *Headers) {
	*out = *in
	if in.CustomRequestHeaders != nil {
		in, out := &in.CustomRequestHeaders, &out.CustomRequestHeaders
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.CustomResponseHeaders != nil {
		in, out := &in.CustomResponseHeaders, &out.CustomResponseHeaders
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.AccessControlAllowHeaders != nil {
		in, out := &in.AccessControlAllowHeaders, &out.AccessControlAllowHeaders
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.AccessControlAllowMethods != nil {
		in, out := &in.AccessControlAllowMethods, &out.AccessControlAllowMethods
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.AccessControlAllowOriginList != nil {
		in, out := &in.AccessControlAllowOriginList, &out.AccessControlAllowOriginList
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.AccessControlExposeHeaders != nil {
		in, out := &in.AccessControlExposeHeaders, &out.AccessControlExposeHeaders
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.AllowedHosts != nil {
		in, out := &in.AllowedHosts, &out.AllowedHosts
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.HostsProxyHeaders != nil {
		in, out := &in.HostsProxyHeaders, &out.HostsProxyHeaders
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.SSLProxyHeaders != nil {
		in, out := &in.SSLProxyHeaders, &out.SSLProxyHeaders
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Headers.
func (in *Headers) DeepCopy() *Headers {
	if in == nil {
		return nil
	}
	out := new(Headers)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IPStrategy) DeepCopyInto(out *IPStrategy) {
	*out = *in
	if in.ExcludedIPs != nil {
		in, out := &in.ExcludedIPs, &out.ExcludedIPs
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IPStrategy.
func (in *IPStrategy) DeepCopy() *IPStrategy {
	if in == nil {
		return nil
	}
	out := new(IPStrategy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IPWhiteList) DeepCopyInto(out *IPWhiteList) {
	*out = *in
	if in.SourceRange != nil {
		in, out := &in.SourceRange, &out.SourceRange
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.IPStrategy != nil {
		in, out := &in.IPStrategy, &out.IPStrategy
		*out = new(IPStrategy)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IPWhiteList.
func (in *IPWhiteList) DeepCopy() *IPWhiteList {
	if in == nil {
		return nil
	}
	out := new(IPWhiteList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *InFlightReq) DeepCopyInto(out *InFlightReq) {
	*out = *in
	if in.SourceCriterion != nil {
		in, out := &in.SourceCriterion, &out.SourceCriterion
		*out = new(SourceCriterion)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new InFlightReq.
func (in *InFlightReq) DeepCopy() *InFlightReq {
	if in == nil {
		return nil
	}
	out := new(InFlightReq)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IngressRoute) DeepCopyInto(out *IngressRoute) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IngressRoute.
func (in *IngressRoute) DeepCopy() *IngressRoute {
	if in == nil {
		return nil
	}
	out := new(IngressRoute)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IngressRoute) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IngressRouteList) DeepCopyInto(out *IngressRouteList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]*IngressRoute, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(IngressRoute)
				(*in).DeepCopyInto(*out)
			}
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IngressRouteList.
func (in *IngressRouteList) DeepCopy() *IngressRouteList {
	if in == nil {
		return nil
	}
	out := new(IngressRouteList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IngressRouteList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IngressRouteSpec) DeepCopyInto(out *IngressRouteSpec) {
	*out = *in
	if in.Routes != nil {
		in, out := &in.Routes, &out.Routes
		*out = make([]Route, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.EntryPoints != nil {
		in, out := &in.EntryPoints, &out.EntryPoints
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.TLS != nil {
		in, out := &in.TLS, &out.TLS
		*out = new(TLS)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IngressRouteSpec.
func (in *IngressRouteSpec) DeepCopy() *IngressRouteSpec {
	if in == nil {
		return nil
	}
	out := new(IngressRouteSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *LoadBalancerSpec) DeepCopyInto(out *LoadBalancerSpec) {
	*out = *in
	if in.Sticky != nil {
		in, out := &in.Sticky, &out.Sticky
		*out = new(Sticky)
		(*in).DeepCopyInto(*out)
	}
	if in.PassHostHeader != nil {
		in, out := &in.PassHostHeader, &out.PassHostHeader
		*out = new(bool)
		**out = **in
	}
	if in.ResponseForwarding != nil {
		in, out := &in.ResponseForwarding, &out.ResponseForwarding
		*out = new(ResponseForwarding)
		**out = **in
	}
	if in.Weight != nil {
		in, out := &in.Weight, &out.Weight
		*out = new(int)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new LoadBalancerSpec.
func (in *LoadBalancerSpec) DeepCopy() *LoadBalancerSpec {
	if in == nil {
		return nil
	}
	out := new(LoadBalancerSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Middleware) DeepCopyInto(out *Middleware) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Middleware.
func (in *Middleware) DeepCopy() *Middleware {
	if in == nil {
		return nil
	}
	out := new(Middleware)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *Middleware) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MiddlewareList) DeepCopyInto(out *MiddlewareList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]*Middleware, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(Middleware)
				(*in).DeepCopyInto(*out)
			}
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MiddlewareList.
func (in *MiddlewareList) DeepCopy() *MiddlewareList {
	if in == nil {
		return nil
	}
	out := new(MiddlewareList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *MiddlewareList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MiddlewareRef) DeepCopyInto(out *MiddlewareRef) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MiddlewareRef.
func (in *MiddlewareRef) DeepCopy() *MiddlewareRef {
	if in == nil {
		return nil
	}
	out := new(MiddlewareRef)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MiddlewareSpec) DeepCopyInto(out *MiddlewareSpec) {
	*out = *in
	if in.AddPrefix != nil {
		in, out := &in.AddPrefix, &out.AddPrefix
		*out = new(AddPrefix)
		**out = **in
	}
	if in.StripPrefix != nil {
		in, out := &in.StripPrefix, &out.StripPrefix
		*out = new(StripPrefix)
		(*in).DeepCopyInto(*out)
	}
	if in.StripPrefixRegex != nil {
		in, out := &in.StripPrefixRegex, &out.StripPrefixRegex
		*out = new(StripPrefixRegex)
		(*in).DeepCopyInto(*out)
	}
	if in.ReplacePath != nil {
		in, out := &in.ReplacePath, &out.ReplacePath
		*out = new(ReplacePath)
		**out = **in
	}
	if in.ReplacePathRegex != nil {
		in, out := &in.ReplacePathRegex, &out.ReplacePathRegex
		*out = new(ReplacePathRegex)
		**out = **in
	}
	if in.Chain != nil {
		in, out := &in.Chain, &out.Chain
		*out = new(Chain)
		(*in).DeepCopyInto(*out)
	}
	if in.IPWhiteList != nil {
		in, out := &in.IPWhiteList, &out.IPWhiteList
		*out = new(IPWhiteList)
		(*in).DeepCopyInto(*out)
	}
	if in.Headers != nil {
		in, out := &in.Headers, &out.Headers
		*out = new(Headers)
		(*in).DeepCopyInto(*out)
	}
	if in.Errors != nil {
		in, out := &in.Errors, &out.Errors
		*out = new(ErrorPage)
		(*in).DeepCopyInto(*out)
	}
	if in.RateLimit != nil {
		in, out := &in.RateLimit, &out.RateLimit
		*out = new(RateLimit)
		(*in).DeepCopyInto(*out)
	}
	if in.RedirectRegex != nil {
		in, out := &in.RedirectRegex, &out.RedirectRegex
		*out = new(RedirectRegex)
		**out = **in
	}
	if in.RedirectScheme != nil {
		in, out := &in.RedirectScheme, &out.RedirectScheme
		*out = new(RedirectScheme)
		**out = **in
	}
	if in.BasicAuth != nil {
		in, out := &in.BasicAuth, &out.BasicAuth
		*out = new(BasicAuth)
		**out = **in
	}
	if in.DigestAuth != nil {
		in, out := &in.DigestAuth, &out.DigestAuth
		*out = new(DigestAuth)
		**out = **in
	}
	if in.ForwardAuth != nil {
		in, out := &in.ForwardAuth, &out.ForwardAuth
		*out = new(ForwardAuth)
		(*in).DeepCopyInto(*out)
	}
	if in.InFlightReq != nil {
		in, out := &in.InFlightReq, &out.InFlightReq
		*out = new(InFlightReq)
		(*in).DeepCopyInto(*out)
	}
	if in.Buffering != nil {
		in, out := &in.Buffering, &out.Buffering
		*out = new(Buffering)
		**out = **in
	}
	if in.CircuitBreaker != nil {
		in, out := &in.CircuitBreaker, &out.CircuitBreaker
		*out = new(CircuitBreaker)
		**out = **in
	}
	if in.Compress != nil {
		in, out := &in.Compress, &out.Compress
		*out = new(Compress)
		(*in).DeepCopyInto(*out)
	}
	if in.PassTLSClientCert != nil {
		in, out := &in.PassTLSClientCert, &out.PassTLSClientCert
		*out = new(PassTLSClientCert)
		(*in).DeepCopyInto(*out)
	}
	if in.Retry != nil {
		in, out := &in.Retry, &out.Retry
		*out = new(Retry)
		**out = **in
	}
	if in.ContentType != nil {
		in, out := &in.ContentType, &out.ContentType
		*out = new(ContentType)
		**out = **in
	}
	if in.Plugin != nil {
		in, out := &in.Plugin, &out.Plugin
		*out = make(map[string]PluginConf, len(*in))
		for key, val := range *in {
			(*out)[key] = *val.DeepCopy()
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MiddlewareSpec.
func (in *MiddlewareSpec) DeepCopy() *MiddlewareSpec {
	if in == nil {
		return nil
	}
	out := new(MiddlewareSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PassTLSClientCert) DeepCopyInto(out *PassTLSClientCert) {
	*out = *in
	if in.Info != nil {
		in, out := &in.Info, &out.Info
		*out = new(TLSClientCertificateInfo)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PassTLSClientCert.
func (in *PassTLSClientCert) DeepCopy() *PassTLSClientCert {
	if in == nil {
		return nil
	}
	out := new(PassTLSClientCert)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RateLimit) DeepCopyInto(out *RateLimit) {
	*out = *in
	if in.SourceCriterion != nil {
		in, out := &in.SourceCriterion, &out.SourceCriterion
		*out = new(SourceCriterion)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RateLimit.
func (in *RateLimit) DeepCopy() *RateLimit {
	if in == nil {
		return nil
	}
	out := new(RateLimit)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RedirectRegex) DeepCopyInto(out *RedirectRegex) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RedirectRegex.
func (in *RedirectRegex) DeepCopy() *RedirectRegex {
	if in == nil {
		return nil
	}
	out := new(RedirectRegex)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RedirectScheme) DeepCopyInto(out *RedirectScheme) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RedirectScheme.
func (in *RedirectScheme) DeepCopy() *RedirectScheme {
	if in == nil {
		return nil
	}
	out := new(RedirectScheme)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ReplacePath) DeepCopyInto(out *ReplacePath) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ReplacePath.
func (in *ReplacePath) DeepCopy() *ReplacePath {
	if in == nil {
		return nil
	}
	out := new(ReplacePath)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ReplacePathRegex) DeepCopyInto(out *ReplacePathRegex) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ReplacePathRegex.
func (in *ReplacePathRegex) DeepCopy() *ReplacePathRegex {
	if in == nil {
		return nil
	}
	out := new(ReplacePathRegex)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ResponseForwarding) DeepCopyInto(out *ResponseForwarding) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ResponseForwarding.
func (in *ResponseForwarding) DeepCopy() *ResponseForwarding {
	if in == nil {
		return nil
	}
	out := new(ResponseForwarding)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Retry) DeepCopyInto(out *Retry) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Retry.
func (in *Retry) DeepCopy() *Retry {
	if in == nil {
		return nil
	}
	out := new(Retry)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Route) DeepCopyInto(out *Route) {
	*out = *in
	if in.Services != nil {
		in, out := &in.Services, &out.Services
		*out = make([]Service, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.Middlewares != nil {
		in, out := &in.Middlewares, &out.Middlewares
		*out = make([]MiddlewareRef, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Route.
func (in *Route) DeepCopy() *Route {
	if in == nil {
		return nil
	}
	out := new(Route)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Service) DeepCopyInto(out *Service) {
	*out = *in
	in.LoadBalancerSpec.DeepCopyInto(&out.LoadBalancerSpec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Service.
func (in *Service) DeepCopy() *Service {
	if in == nil {
		return nil
	}
	out := new(Service)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SourceCriterion) DeepCopyInto(out *SourceCriterion) {
	*out = *in
	if in.IPStrategy != nil {
		in, out := &in.IPStrategy, &out.IPStrategy
		*out = new(IPStrategy)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SourceCriterion.
func (in *SourceCriterion) DeepCopy() *SourceCriterion {
	if in == nil {
		return nil
	}
	out := new(SourceCriterion)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Sticky) DeepCopyInto(out *Sticky) {
	*out = *in
	if in.Cookie != nil {
		in, out := &in.Cookie, &out.Cookie
		*out = new(Cookie)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Sticky.
func (in *Sticky) DeepCopy() *Sticky {
	if in == nil {
		return nil
	}
	out := new(Sticky)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *StripPrefix) DeepCopyInto(out *StripPrefix) {
	*out = *in
	if in.Prefixes != nil {
		in, out := &in.Prefixes, &out.Prefixes
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new StripPrefix.
func (in *StripPrefix) DeepCopy() *StripPrefix {
	if in == nil {
		return nil
	}
	out := new(StripPrefix)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *StripPrefixRegex) DeepCopyInto(out *StripPrefixRegex) {
	*out = *in
	if in.Regex != nil {
		in, out := &in.Regex, &out.Regex
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new StripPrefixRegex.
func (in *StripPrefixRegex) DeepCopy() *StripPrefixRegex {
	if in == nil {
		return nil
	}
	out := new(StripPrefixRegex)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TLS) DeepCopyInto(out *TLS) {
	*out = *in
	if in.Options != nil {
		in, out := &in.Options, &out.Options
		*out = new(TLSOptionRef)
		**out = **in
	}
	if in.Store != nil {
		in, out := &in.Store, &out.Store
		*out = new(TLSStoreRef)
		**out = **in
	}
	if in.Domains != nil {
		in, out := &in.Domains, &out.Domains
		*out = make([]Domain, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TLS.
func (in *TLS) DeepCopy() *TLS {
	if in == nil {
		return nil
	}
	out := new(TLS)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TLSCLientCertificateDNInfo) DeepCopyInto(out *TLSCLientCertificateDNInfo) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TLSCLientCertificateDNInfo.
func (in *TLSCLientCertificateDNInfo) DeepCopy() *TLSCLientCertificateDNInfo {
	if in == nil {
		return nil
	}
	out := new(TLSCLientCertificateDNInfo)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TLSClientCertificateInfo) DeepCopyInto(out *TLSClientCertificateInfo) {
	*out = *in
	if in.Subject != nil {
		in, out := &in.Subject, &out.Subject
		*out = new(TLSCLientCertificateDNInfo)
		**out = **in
	}
	if in.Issuer != nil {
		in, out := &in.Issuer, &out.Issuer
		*out = new(TLSCLientCertificateDNInfo)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TLSClientCertificateInfo.
func (in *TLSClientCertificateInfo) DeepCopy() *TLSClientCertificateInfo {
	if in == nil {
		return nil
	}
	out := new(TLSClientCertificateInfo)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TLSOptionRef) DeepCopyInto(out *TLSOptionRef) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TLSOptionRef.
func (in *TLSOptionRef) DeepCopy() *TLSOptionRef {
	if in == nil {
		return nil
	}
	out := new(TLSOptionRef)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TLSStoreRef) DeepCopyInto(out *TLSStoreRef) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TLSStoreRef.
func (in *TLSStoreRef) DeepCopy() *TLSStoreRef {
	if in == nil {
		return nil
	}
	out := new(TLSStoreRef)
	in.DeepCopyInto(out)
	return out
}
