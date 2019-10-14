/*
Copyright 2016 The Kubernetes Authors.

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

// Note: the example only works with the code within the same release/branch.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/mitchellh/colorstring"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	//
	// Uncomment to load all auth plugins
	// _ "k8s.io/client-go/plugin/pkg/client/auth"
	//
	// Or uncomment to load specific auth plugins
	// _ "k8s.io/client-go/plugin/pkg/client/auth/azure"
	// _ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	// _ "k8s.io/client-go/plugin/pkg/client/auth/oidc"
	// _ "k8s.io/client-go/plugin/pkg/client/auth/openstack"
)

var (
	days   int
	months int
	years  int
)

var sunsetSignatureAlgorithms = map[x509.SignatureAlgorithm]sunsetSignatureAlgorithm{
	x509.MD2WithRSA: {
		name: "MD2 with RSA",
		date: time.Now(),
	},
	x509.MD5WithRSA: {
		name: "MD5 with RSA",
		date: time.Now(),
	},
	x509.SHA1WithRSA: {
		name: "SHA1 with RSA",
		date: time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
	},
	x509.DSAWithSHA1: {
		name: "DSA with SHA1",
		date: time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
	},
	x509.ECDSAWithSHA1: {
		name: "ECDSA with SHA1",
		date: time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
	},
}

func main() {
	var kubeconfig *string
	if home := homeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}
	flag.Parse()

	// use the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		panic(err.Error())
	}

	// create the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	// we will list every ingress using tls. Why? to check for expiration date and warn
	ingress, err := clientset.ExtensionsV1beta1().Ingresses("").List(metav1.ListOptions{})
	if err != nil {
		panic(err.Error())
	}

	now := time.Now()
	twarn := now.AddDate(years, months, days)

	hosts := hosts{}

	// there must be a better way!
	for _, s := range ingress.Items {
		for p := range s.Spec.TLS {
			for _, h := range s.Spec.TLS[p].Hosts {
				certs, _ := checkHost(h, twarn)
				hosts = append(hosts, host{name: h, certs: certs})
			}
		}

	}

	w := tabwriter.NewWriter(os.Stdout, 20, 1, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tSUBJECT\tISSUER\tALGO\tEXPIRES\tSUNSET DATE\tERROR")

	// now we should iterate over hosts
	for i := 0; i < len(hosts); i++ {
		for _, cert := range hosts[i].certs {
			sunset := ""
			if cert.sunset != nil {
				sunset = cert.sunset.date.Format("Jan 02, 2006")

			}
			expires := cert.expires
			if cert.warn {
				expires = colorstring.Color("[red]" + cert.expires + "[reset]")
			}
			error := cert.error
			if error != "" {
				error = colorstring.Color("[red]" + cert.error + "[reset]")
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", cert.name, cert.subject, cert.issuer, cert.algo, expires, sunset, error)
		}
	}
	w.Flush()
}

func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return os.Getenv("USERPROFILE") // windows
}

type hosts []host

func (h hosts) Len() int           { return len(h) }
func (h hosts) Less(i, j int) bool { return h[i].name < h[j].name }
func (h hosts) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

type host struct {
	name  string
	certs map[string]certificate
}

type certificate struct {
	name    string
	subject string
	algo    string
	issuer  string
	expires string
	warn    bool
	error   string
	sunset  *sunsetSignatureAlgorithm
}

type sunsetSignatureAlgorithm struct {
	name string    // Human readable name of the signature algorithm.
	date time.Time // Date the signature algorithm will be sunset.
}

func checkHost(h string, twarn time.Time) (map[string]certificate, error) {
	if !strings.Contains(h, ":") {
		// default to 443
		h += ":443"
	}
	c, err := tls.Dial("tcp", h, nil)
	if err != nil {
		switch cerr := err.(type) {
		case x509.CertificateInvalidError:
			ht := createHost(h, twarn, cerr.Cert)
			ht.error = err.Error()
			return map[string]certificate{
				string(cerr.Cert.Signature): ht,
			}, nil
		case x509.UnknownAuthorityError:
			ht := createHost(h, twarn, cerr.Cert)
			ht.error = err.Error()
			return map[string]certificate{
				string(cerr.Cert.Signature): ht,
			}, nil
		case x509.HostnameError:
			ht := createHost(h, twarn, cerr.Certificate)
			ht.error = err.Error()
			return map[string]certificate{
				string(cerr.Certificate.Signature): ht,
			}, nil
		}
		return nil, fmt.Errorf("tcp dial %s failed: %v", h, err)
	}
	defer c.Close()

	certs := make(map[string]certificate)
	for _, chain := range c.ConnectionState().VerifiedChains {
		for _, cert := range chain {
			if _, checked := certs[string(cert.Signature)]; checked {
				continue
			}

			ht := createHost(h, twarn, cert)

			certs[string(cert.Signature)] = ht
		}
	}
	return certs, nil
}

func createHost(name string, twarn time.Time, cert *x509.Certificate) certificate {
	host := certificate{
		name:    name,
		subject: cert.Subject.CommonName,
		issuer:  cert.Issuer.CommonName,
		algo:    cert.SignatureAlgorithm.String(),
	}

	// check the expiration
	if twarn.After(cert.NotAfter) {
		host.warn = true
	}
	expiresIn := int64(time.Until(cert.NotAfter).Hours())
	if expiresIn <= 48 {
		host.expires = fmt.Sprintf("%d hours", expiresIn)
	} else {
		host.expires = fmt.Sprintf("%d days", expiresIn/24)
	}

	// Check the signature algorithm, ignoring the root certificate.
	if alg, exists := sunsetSignatureAlgorithms[cert.SignatureAlgorithm]; exists {
		if cert.NotAfter.Equal(alg.date) || cert.NotAfter.After(alg.date) {
			host.warn = true
		}
		host.sunset = &alg
	}

	return host
}
