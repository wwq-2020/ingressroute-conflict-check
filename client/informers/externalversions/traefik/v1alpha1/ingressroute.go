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

// Code generated by informer-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"
	time "time"

	traefikv1alpha1 "github.com/wwq-2020/ingressroute-conflict-check/apis/traefik/v1alpha1"
	versioned "github.com/wwq-2020/ingressroute-conflict-check/client/clientset/versioned"
	internalinterfaces "github.com/wwq-2020/ingressroute-conflict-check/client/informers/externalversions/internalinterfaces"
	v1alpha1 "github.com/wwq-2020/ingressroute-conflict-check/client/listers/traefik/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// IngressRouteInformer provides access to a shared informer and lister for
// IngressRoutes.
type IngressRouteInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1alpha1.IngressRouteLister
}

type ingressRouteInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
	namespace        string
}

// NewIngressRouteInformer constructs a new informer for IngressRoute type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewIngressRouteInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredIngressRouteInformer(client, namespace, resyncPeriod, indexers, nil)
}

// NewFilteredIngressRouteInformer constructs a new informer for IngressRoute type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredIngressRouteInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.TraefikV1alpha1().IngressRoutes(namespace).List(context.TODO(), options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.TraefikV1alpha1().IngressRoutes(namespace).Watch(context.TODO(), options)
			},
		},
		&traefikv1alpha1.IngressRoute{},
		resyncPeriod,
		indexers,
	)
}

func (f *ingressRouteInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredIngressRouteInformer(client, f.namespace, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *ingressRouteInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&traefikv1alpha1.IngressRoute{}, f.defaultInformer)
}

func (f *ingressRouteInformer) Lister() v1alpha1.IngressRouteLister {
	return v1alpha1.NewIngressRouteLister(f.Informer().GetIndexer())
}
