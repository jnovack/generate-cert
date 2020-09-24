package main

import (
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"log"

	gencert "github.com/jnovack/generate-cert/lib"
)

func writeCert(c *gencert.Cert, rootFilename string) error {
	pubkey := "temp/" + rootFilename + ".pem"
	if err := ioutil.WriteFile(pubkey, c.PublicBytes, 0666); err != nil {
		return err
	}
	privkey := "temp/" + rootFilename + ".key"
	if err := ioutil.WriteFile(privkey, c.PrivateBytes, 0600); err != nil {
		return err
	}
	return nil
}

func main() {
	// version := flag.Bool("version", false, "Print the version string and exit")
	// host := flag.String("host", "", "Comma-separated hostnames and IPs to generate a certificate for")
	// validFor := flag.Duration("duration", 365*24*time.Hour, "Duration that certificate is valid for")
	// organization := flag.String("organization", "Acme", "Company to issue the cert to")
	// flag.Parse()
	// if *version {
	// 	fmt.Fprintf(os.Stderr, "generate-cert version %s\n", gencert.Version)
	// 	os.Exit(0)
	// }

	values := pkix.Name{
		Organization: []string{"ACME Company"},
	}

	// Root CA
	rootCA, err := gencert.GenerateRoot(values)
	if err != nil {
		log.Fatal(err)
	}
	if err := writeCert(rootCA, "root"); err != nil {
		log.Fatal(err)
	}

	// Intermediate CA for Servers
	svrCA, err := gencert.GenerateIntermediate(values, rootCA)
	if err != nil {
		log.Fatal(err)
	}
	if err := writeCert(svrCA, "intermediate-server"); err != nil {
		log.Fatal(err)
	}

	// Intermediate CA for Clients
	cliCA, err := gencert.GenerateIntermediate(values, rootCA)
	if err != nil {
		log.Fatal(err)
	}
	if err := writeCert(cliCA, "intermediate-client"); err != nil {
		log.Fatal(err)
	}

	// Server Certs
	for i := 1; i < 4; i++ {
		name := fmt.Sprintf("server%d.local", i)
		server, err := gencert.GenerateServer(values, svrCA, []string{name})
		if err != nil {
			log.Fatal(err)
		}
		if err := writeCert(server, name); err != nil {
			log.Fatal(err)
		}
	}

	// Client Certs
	for i := 1; i < 4; i++ {
		name := fmt.Sprintf("client%d", i)
		client, err := gencert.GenerateClient(values, cliCA, []string{name})
		if err != nil {
			log.Fatal(err)
		}
		if err := writeCert(client, name); err != nil {
			log.Fatal(err)
		}
	}

}
