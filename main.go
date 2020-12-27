package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vulcand/predicate"
	"github.com/wwq-2020/ingressroute-conflict-check/apis/traefik/v1alpha1"
	"github.com/wwq-2020/ingressroute-conflict-check/client/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"

	admissionv1 "k8s.io/api/admission/v1"
)

var clientset versioned.Interface

func init() {
	kubeConfigPath := os.ExpandEnv("$HOME/.kube/config")
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	if err != nil {
		logrus.Fatal(err)
	}

	clientset, err = versioned.NewForConfig(config)
	if err != nil {
		logrus.Fatal(err)
	}
}

func main() {
	http.HandleFunc("/validating/check-conflict", func(w http.ResponseWriter, r *http.Request) {
		reviewReq := &admissionv1.AdmissionReview{}
		if err := json.NewDecoder(r.Body).Decode(reviewReq); err != nil {
			return
		}

		if reviewReq.Request == nil {
			return
		}
		ingressRoute := &v1alpha1.IngressRoute{}
		if err := json.Unmarshal(reviewReq.Request.Object.Raw, ingressRoute); err != nil {
			return
		}
		isConflict, err := checkConflict(ingressRoute)
		if err != nil {
			return
		}

		resp := &admissionv1.AdmissionResponse{
			UID:     reviewReq.Request.UID,
			Allowed: !isConflict,
			Result: &metav1.Status{
				Code:    http.StatusOK,
				Message: "",
			},
		}

		reviewResp := admissionv1.AdmissionReview{
			TypeMeta: reviewReq.TypeMeta,
			Response: resp,
		}
		if err := json.NewEncoder(w).Encode(reviewResp); err != nil {
			return
		}
	})

	http.ListenAndServe(":8081", nil)
}

func checkConflict(srcIngressroute *v1alpha1.IngressRoute) (bool, error) {
	srcCheckItems := collectCheckItem(srcIngressroute)
	destIngressRouteList, err := clientset.TraefikV1alpha1().IngressRoutes("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return false, errors.WithStack(err)
	}
	for _, destIngressRoute := range destIngressRouteList.Items {
		destCheckItems := collectCheckItem(destIngressRoute)
		for _, srcCheckItem := range srcCheckItems {
			for _, destCheckItem := range destCheckItems {
				if err := srcCheckItem.checkConflict(destCheckItem); err != nil {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

func collectCheckItem(ingressRoute *v1alpha1.IngressRoute) []*checkItem {
	var checkItems []*checkItem
	for _, each := range ingressRoute.Spec.Routes {
		c, err := parser.Parse(each.Match)
		if err != nil {
			continue
		}
		r := newRoute()
		buildRoute(r, c.(condition))
		checkItems = append(checkItems, collectFromRoutes([]*route{r})...)
	}
	return checkItems
}

var parser predicate.Parser

type route struct {
	hosts        []string
	hostRegexps  []string
	pathPrefixes []string
	headers      map[string]string
	children     []*route
}

type checkItem struct {
	host       string
	hostRegexp string
	pathPrefix string
}

func (r *checkItem) checkConflict(given *checkItem) error {
	other := r.pathPrefix == given.pathPrefix
	if !other {
		return nil
	}
	if r.host != "" && given.host != "" && r.host == given.host {
		return errors.New("conflict")
	}
	if r.hostRegexp != "" && given.hostRegexp != "" && r.hostRegexp == given.hostRegexp {
		return errors.New("conflict")
	}
	return nil
}

func (r *route) newRoute() *route {
	child := newRoute()
	r.children = append(r.children, child)
	return child
}

func newRoute() *route {
	return &route{}

}

type condition interface {
	Name() string
}

type unaryCondition struct {
	hosts          []string
	hostRegexps    []string
	paths          []string
	pathPrefixes   []string
	headers        map[string]string
	headersRegexps []string
	methods        []string
	queries        []string
}

func (uc *unaryCondition) Name() string {
	return "unaryCondition"
}

type op string

const (
	andOp op = "and"
	orOp  op = "or"
)

type binaryCondition struct {
	Left  condition
	Right condition
	Op    op
}

func (bc *binaryCondition) Name() string {
	return "binaryCondition"
}

func andFunc(left, right condition) condition {
	return &binaryCondition{
		Left:  left,
		Right: right,
		Op:    andOp,
	}
}

func orFunc(left, right condition) condition {
	return &binaryCondition{
		Left:  left,
		Right: right,
		Op:    orOp,
	}
}

func host(hosts ...string) condition {
	return &unaryCondition{
		hosts: hosts,
	}
}

func hostRegexp(hostRegexps ...string) condition {
	return &unaryCondition{
		hostRegexps: hostRegexps,
	}
}

func path(paths ...string) condition {
	return &unaryCondition{
		paths: paths,
	}
}

func pathPrefix(pathPrefixes ...string) condition {
	return &unaryCondition{
		pathPrefixes: pathPrefixes,
	}
}

func method(methods ...string) condition {
	return &unaryCondition{
		methods: methods,
	}
}

func headers(headers ...string) condition {
	kv := make(map[string]string)
	for i := 1; i < len(headers); i = i + 2 {
		kv[headers[i-1]] = headers[i]
	}
	return &unaryCondition{
		headers: kv,
	}
}

func headersRegexp(headersRegexps ...string) condition {
	return &unaryCondition{
		headersRegexps: headersRegexps,
	}
}

func query(queries ...string) condition {
	return &unaryCondition{
		queries: queries,
	}
}

func init() {
	parserFuncs := map[string]interface{}{
		"Host":          host,
		"HostHeader":    host,
		"HostRegexp":    hostRegexp,
		"Path":          path,
		"PathPrefix":    pathPrefix,
		"Method":        method,
		"Headers":       headers,
		"HeadersRegexp": headersRegexp,
		"Query":         query,
	}

	parserTmp, err := predicate.NewParser(predicate.Def{
		Operators: predicate.Operators{
			AND: andFunc,
			OR:  orFunc,
		},
		Functions: parserFuncs,
	})
	if err != nil {
		panic(err)
	}
	parser = parserTmp
}

func collectFromRoutes(routes []*route) []*checkItem {
	var rets []*checkItem
	for _, route := range routes {
		if len(route.children) == 0 {
			var curRetTmp []*checkItem
			var newRetTmp []*checkItem

			for _, host := range route.hosts {
				curRetTmp = append(curRetTmp, &checkItem{
					host: host,
				})
			}
			for _, hostRegexp := range route.hostRegexps {
				curRetTmp = append(curRetTmp, &checkItem{
					hostRegexp: hostRegexp,
				})
			}

			for _, pathPrefix := range route.pathPrefixes {
				for _, each := range curRetTmp {
					itemTmp := &checkItem{
						host:       each.host,
						hostRegexp: each.hostRegexp,
						pathPrefix: each.pathPrefix,
					}
					itemTmp.pathPrefix = pathPrefix
					newRetTmp = append(newRetTmp, itemTmp)
				}
			}
			if len(newRetTmp) != 0 {
				curRetTmp = newRetTmp
			}
			rets = append(rets, curRetTmp...)

			newRetTmp = nil
			continue
		}
		items := collectFromRoutes(route.children)
		for _, item := range items {
			var newRetTmp []*checkItem
			curRetTmp := []*checkItem{item}
			if item.host == "" && item.hostRegexp == "" {
				for _, each := range route.hosts {
					itemTmp := &checkItem{
						host:       item.host,
						hostRegexp: item.hostRegexp,
						pathPrefix: item.pathPrefix,
					}
					itemTmp.host = each
					newRetTmp = append(newRetTmp, itemTmp)
				}
				for _, each := range route.hostRegexps {
					itemTmp := &checkItem{
						host:       item.host,
						hostRegexp: item.hostRegexp,
						pathPrefix: item.pathPrefix,
					}
					itemTmp.hostRegexp = each
					newRetTmp = append(newRetTmp, itemTmp)
				}
			}
			if len(newRetTmp) != 0 {
				curRetTmp = newRetTmp
			}
			newRetTmp = nil

			if item.pathPrefix == "" {
				for _, pathPrefix := range route.pathPrefixes {
					for _, each := range curRetTmp {
						itemTmp := &checkItem{
							host:       each.host,
							hostRegexp: each.hostRegexp,
							pathPrefix: each.pathPrefix,
						}
						itemTmp.pathPrefix = pathPrefix
						newRetTmp = append(newRetTmp, itemTmp)
					}
				}
			}
			if len(newRetTmp) != 0 {
				curRetTmp = newRetTmp
			}
			newRetTmp = nil
			rets = append(rets, curRetTmp...)
		}
	}

	return rets
}

func buildRoute(r *route, c condition) {
	switch ct := c.(type) {
	case *unaryCondition:
		if len(ct.hosts) != 0 {
			r.hosts = ct.hosts
		}
		if len(ct.hostRegexps) != 0 {
			r.hostRegexps = ct.hostRegexps
		}
		if len(ct.pathPrefixes) != 0 {
			r.pathPrefixes = ct.pathPrefixes
		}
		if len(ct.headers) != 0 {
			r.headers = ct.headers
		}
	case *binaryCondition:
		if ct.Op == andOp {
			buildRoute(r, ct.Left)
			buildRoute(r, ct.Right)
			return
		}
		left := r.newRoute()
		buildRoute(left, ct.Left)
		right := r.newRoute()
		buildRoute(right, ct.Right)
	}
}
