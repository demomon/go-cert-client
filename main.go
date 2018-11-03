package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/lizrice/secure-connections/utils"
	"io/ioutil"
	"net/http"
	"os"
)

func main() {
	certsFolder := flag.String("cf", "/", "Location of the folder containing TLS cert.pem and key.pem files")
	caFolder := flag.String("caf", "/", "Location of the folder containing TLS cert.pem and key.pem files of the CA")
	flag.Parse()

	client := getClient(*caFolder, *certsFolder)
	response, err := client.Get("https://127.0.0.1.nip.io:8080")

	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}

	defer response.Body.Close()
	body, _ := ioutil.ReadAll(response.Body)

	fmt.Printf("Status: %s, Body: %s\n", response.Status, string(body))
}

func getClient(caFolder string, certsFolder string) *http.Client {

	data, _ := ioutil.ReadFile(caFolder + "/minica.pem")
	cp, _ := x509.SystemCertPool()
	cp.AppendCertsFromPEM(data)

	config := &tls.Config{
		RootCAs:               cp,
		GetClientCertificate:  utils.ClientCertReqFunc(certsFolder+"/cert.pem", certsFolder+"/key.pem"),
		VerifyPeerCertificate: utils.CertificateChains,
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	return client
}
