package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	log "github.com/sirupsen/logrus"
	"github.com/vulcand/oxy/buffer"
	"github.com/vulcand/oxy/forward"
	"github.com/vulcand/oxy/roundrobin"
	goji "goji.io"
	"goji.io/pat"
)

type Config struct {
	Target             *string
	ServiceRootURL     *string
	ServiceCertificate *string
	ServiceKey         *string
	IdpMetadata        *string
	HttpsCertificate   *string
	HttpsKey           *string
}

func readIdpMetadata(path *string) (*saml.Metadata, error) {
	data, err := ioutil.ReadFile(*path)
	if err != nil {
		log.WithFields(log.Fields{"path": *path}).Fatal(err)
		return nil, err
	}

	idpMetadata := &saml.Metadata{}
	err = xml.Unmarshal(data, idpMetadata)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	return idpMetadata, nil
}

func main() {
	var C Config

	C.Target = flag.String("target", "", "Target for the reverse proxy")
	C.ServiceRootURL = flag.String("service-root-url", "", "Root URL for this service")
	C.ServiceCertificate = flag.String("service-certificate", "", "Path to a certificate for the SP")
	C.ServiceKey = flag.String("service-key", "", "Path to a private key for the SP")
	C.IdpMetadata = flag.String("idp-metadata", "", "Path to IdP metadata")
	C.HttpsCertificate = flag.String("-https-certificate", "", "Optional path to https certificate")
	C.HttpsKey = flag.String("-https-key", "", "Optional path to https key")
	flag.Parse()

	log.SetFormatter(&log.JSONFormatter{})
	log.SetOutput(os.Stdout)
	logLevel, err := log.ParseLevel("info")
	if err != nil {
		log.Fatal(err)
	}
	log.SetLevel(logLevel)

	go func() {
		for {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			log.WithFields(log.Fields{
				"alloc":              fmt.Sprintf("%v", m.Alloc),
				"total-alloc":        fmt.Sprintf("%v", m.TotalAlloc/1024),
				"sys":                fmt.Sprintf("%v", m.Sys/1024),
				"num-gc":             fmt.Sprintf("%v", m.NumGC),
				"goroutines":         fmt.Sprintf("%v", runtime.NumGoroutine()),
				"stop-pause-nanosec": fmt.Sprintf("%v", m.PauseTotalNs),
			}).Warn("Process stats")
			time.Sleep(60 * time.Second)
		}
	}()

	keyPair, err := tls.LoadX509KeyPair(*C.ServiceCertificate, *C.ServiceKey)
	if err != nil {
		log.Fatal("service-key", err)
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		log.Fatal("service-certificate", err)
	}

	rootURL, err := url.Parse(*C.ServiceRootURL)
	if err != nil {
		log.Fatal(err)
	}

	idpMetadata, err := readIdpMetadata(C.IdpMetadata)

	samlSP, _ := samlsp.New(samlsp.Options{
		URL:         *rootURL,
		Key:         keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate: keyPair.Leaf,
		IDPMetadata: idpMetadata,
	})

	// reverse proxy layer
	fwd, err := forward.New()
	if err != nil {
		log.Fatal(err)
	}
	// load balancing layer
	lb, err := roundrobin.New(fwd)
	if err != nil {
		log.Fatal(err)
	}

	// buffer will read the request body and will replay the request again in case if forward returned status
	// corresponding to nework error (e.g. Gateway Timeout)
	buffer, err := buffer.New(lb, buffer.Retry(`IsNetworkError() && Attempts() < 3`))
	if err != nil {
		log.Fatal(err)
	}

	targetURL, err := url.Parse(*C.Target)
	if err != nil {
		log.Fatal(err)
	}
	// add target to the load balancer
	lb.UpsertServer(targetURL)

	// Use mux for explicit paths and so no other routes are accidently exposed
	router := goji.NewMux()

	// This endpoint handles SAML auth flow
	router.Handle(pat.New("/saml/*"), samlSP)
	// These endpoints require valid session cookie
	router.Handle(pat.New("/*"), samlSP.RequireAccount(buffer))

	srv := &http.Server{
		Addr:    "localhost:8080",
		Handler: router,
		// This breaks streaming requests
		ReadTimeout: 45 * time.Second,
		// This breaks long downloads
		WriteTimeout: 45 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	if *C.HttpsKey == "" || *C.HttpsCertificate == "" {
		log.Fatal(srv.ListenAndServe())
	} else {
		log.Fatal(srv.ListenAndServeTLS(*C.HttpsCertificate, *C.HttpsKey))
	}
}
