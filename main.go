package main

import (
	"flag"
	"io/ioutil"
	"log"
	"strings"
	"time"

	gencert "github.com/meterup/generate-cert/lib"
)

func writeCert(c *gencert.Cert, rootFilename string) error {
	pubkey := rootFilename + ".pem"
	if err := ioutil.WriteFile(pubkey, c.PublicBytes, 0666); err != nil {
		return err
	}
	privkey := rootFilename + ".key"
	if err := ioutil.WriteFile(privkey, c.PrivateBytes, 0600); err != nil {
		return err
	}
	return nil
}

func main() {
	host := flag.String("host", "", "Comma-separated hostnames and IPs to generate a certificate for")
	validFor := flag.Duration("duration", 365*24*time.Hour, "Duration that certificate is valid for")
	organization := flag.String("organization", "Acme Co", "Company to issue the cert to")
	flag.Parse()

	hosts := strings.Split(*host, ",")
	certs, err := gencert.Generate(hosts, *organization, *validFor)
	if err != nil {
		log.Fatal(err)
	}

	if err := writeCert(certs.Root, "root"); err != nil {
		log.Fatal(err)
	}
	if err := writeCert(certs.Leaf, "leaf"); err != nil {
		log.Fatal(err)
	}
	if err := writeCert(certs.Client, "client"); err != nil {
		log.Fatal(err)
	}
}
