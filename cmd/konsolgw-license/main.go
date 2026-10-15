// Command konsolgw-license is the vendor's tool for issuing Konsol Gateway
// licences. Keep the private key offline: whoever holds it can mint licences.
//
//	konsolgw-license genkey -out private.key        prints the public key (hex) to compile in
//	konsolgw-license sign -key private.key -customer "PT CNI" -edition pro -days 365 [-nodes 5]
//	konsolgw-license verify -pub <hex> -file license.key
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"haproxy-gui/internal/license"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "genkey":
		err = genkey(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: konsolgw-license genkey|sign|verify [flags]")
	os.Exit(2)
}

func genkey(args []string) error {
	fs := flag.NewFlagSet("genkey", flag.ExitOnError)
	out := fs.String("out", "", "file to write the private key to (mode 0600)")
	_ = fs.Parse(args)
	if *out == "" {
		return fmt.Errorf("-out is required")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, []byte(hex.EncodeToString(priv)+"\n"), 0o600); err != nil {
		return err
	}
	fmt.Println("private key written to", *out, "- keep it offline")
	fmt.Println("public key (build with LICENSE_PUBKEY=<this> bash release.sh):")
	fmt.Println(hex.EncodeToString(pub))
	return nil
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	keyFile := fs.String("key", "", "private key file from genkey")
	customer := fs.String("customer", "", "customer name")
	edition := fs.String("edition", "pro", "community | pro | enterprise")
	days := fs.Int("days", 365, "validity in days")
	nodes := fs.Int("nodes", 0, "fleet node cap (0 = unlimited)")
	_ = fs.Parse(args)

	raw, err := os.ReadFile(*keyFile)
	if err != nil {
		return err
	}
	priv, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("%s is not a private key written by genkey", *keyFile)
	}
	tok, err := license.Sign(ed25519.PrivateKey(priv), license.License{
		Customer: *customer, Edition: license.Edition(*edition),
		NotAfter: time.Now().UTC().AddDate(0, 0, *days), Nodes: *nodes,
	})
	if err != nil {
		return err
	}
	fmt.Println(tok)
	return nil
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	pubHex := fs.String("pub", "", "public key (hex)")
	file := fs.String("file", "", "licence file")
	_ = fs.Parse(args)
	g := license.Load(*pubHex, *file, time.Now())
	fmt.Println(g.Describe())
	return nil
}
