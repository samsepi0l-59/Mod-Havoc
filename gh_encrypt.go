package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"github.com/samsepi0l/Havoc/teamserver/pkg"
)

func main() {
	genKey := flag.Bool("genkey", false, "Generate new 256-bit key")
	encrypt := flag.Bool("encrypt", false, "Encrypt input file")
	decrypt := flag.Bool("decrypt", false, "Decrypt input file")
	inFile := flag.String("in", "", "Input file path")
	outFile := flag.String("out", "", "Output file path")
	key := flag.String("key", "", "Base64 encoded 32-byte key")

	flag.Parse()

	if *genKey {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			log.Fatalf("Key generation failed: %v", err)
		}
		fmt.Println(base64.StdEncoding.EncodeToString(key))
		return
	}

	if *encrypt == *decrypt || (!*encrypt && !*decrypt) {
		log.Fatal("Specify either -encrypt or -decrypt")
	}

	if *inFile == "" || *outFile == "" {
		log.Fatal("Input and output file paths are required")
	}

	data, err := os.ReadFile(*inFile)
	if err != nil {
		log.Fatalf("Read error: %v", err)
	}

	keyBytes, err := base64.StdEncoding.DecodeString(*key)
	if err != nil || len(keyBytes) != 32 {
		log.Fatal("Invalid key: must be 32 bytes base64 encoded")
	}

	chain, err := pkg.NewCryptoChain(keyBytes)
	if err != nil {
		log.Fatalf("Crypto chain initialization failed: %v", err)
	}
	defer chain.Wipe()

	var result []byte
	if *encrypt {
		result, err = chain.Encrypt(data)
	} else {
		result, err = chain.Decrypt(data)
	}
	if err != nil {
		log.Fatalf("Processing failed: %v", err)
	}

	if err := os.WriteFile(*outFile, result, 0600); err != nil {
		log.Fatalf("Write failed: %v", err)
	}

	fmt.Println("Operation successful")
}