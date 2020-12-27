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

// Code generated by lister-gen. DO NOT EDIT.

package v1alpha1

import (
	v1alpha1 "github.com/wwq-2020/ingressroute-conflict-check/apis/traefik/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// IngressRouteLister helps list IngressRoutes.
// All objects returned here must be treated as read-only.
type IngressRouteLister interface {
	// List lists all IngressRoutes in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha1.IngressRoute, err error)
	// IngressRoutes returns an object that can list and get IngressRoutes.
	IngressRoutes(namespace string) IngressRouteNamespaceLister
	IngressRouteListerExpansion
}

// ingressRouteLister implements the IngressRouteLister interface.
type ingressRouteLister struct {
	indexer cache.Indexer
}

// NewIngressRouteLister returns a new IngressRouteLister.
func NewIngressRouteLister(indexer cache.Indexer) IngressRouteLister {
	return &ingressRouteLister{indexer: indexer}
}

// List lists all IngressRoutes in the indexer.
func (s *ingressRouteLister) List(selector labels.Selector) (ret []*v1alpha1.IngressRoute, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha1.IngressRoute))
	})
	return ret, err
}

// IngressRoutes returns an object that can list and get IngressRoutes.
func (s *ingressRouteLister) IngressRoutes(namespace string) IngressRouteNamespaceLister {
	return ingressRouteNamespaceLister{indexer: s.indexer, namespace: namespace}
}

// IngressRouteNamespaceLister helps list and get IngressRoutes.
// All objects returned here must be treated as read-only.
type IngressRouteNamespaceLister interface {
	// List lists all IngressRoutes in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha1.IngressRoute, err error)
	// Get retrieves the IngressRoute from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1alpha1.IngressRoute, error)
	IngressRouteNamespaceListerExpansion
}

// ingressRouteNamespaceLister implements the IngressRouteNamespaceLister
// interface.
type ingressRouteNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
}

// List lists all IngressRoutes in the indexer for a given namespace.
func (s ingressRouteNamespaceLister) List(selector labels.Selector) (ret []*v1alpha1.IngressRoute, err error) {
	err = cache.ListAllByNamespace(s.indexer, s.namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha1.IngressRoute))
	})
	return ret, err
}

// Get retrieves the IngressRoute from the indexer for a given namespace and name.
func (s ingressRouteNamespaceLister) Get(name string) (*v1alpha1.IngressRoute, error) {
	obj, exists, err := s.indexer.GetByKey(s.namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1alpha1.Resource("ingressroute"), name)
	}
	return obj.(*v1alpha1.IngressRoute), nil
}
