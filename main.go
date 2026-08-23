package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"flag"
	"os"
	"strconv"
	"errors"

	"acovia.net/crypter"
	"acovia.net/record"
)

var (
	outputFile string
	key string
	iv string

	cmdMap map[string]func()
)

func main() {

	flag.StringVar(&key, "k", "", "Key")
	flag.Parse()
	
	command := flag.Arg(0)

	cmdMap = map[string]func() {

		"en": en,

		"de": de,

		"setkey": setKey,

		"genkey": genKey,
		
		"gethex": getHex,

	}

	if len(flag.Arg(0)) == 0 {
		record.Error("%v", errors.New("command missing"))
	}

	function, ok := cmdMap[command]

	if !ok {
		record.Error("command not found")
		os.Exit(1)
	}

	function()
}

func en() {

	if len(flag.Arg(1)) == 0 {
		record.Error("%v", errors.New("input file missing"))
	}
	inputFile := flag.Arg(1)

	if len(flag.Arg(2)) != 0 {
		outputFile = flag.Arg(2)
	} else {
		outputFile = inputFile + ".enc"
	}

	key, err := crypter.GetUserKey()
	if err != nil {
		record.Error("%v", err)
		os.Exit(1)
	}

	file, err := os.Open(inputFile)
	if err != nil {
		record.Error("%v", err)
	}

	cipherFile, err := os.Create(outputFile)
	if err != nil {
		record.Error("%v", err)
	}

	aesBlock, err := aes.NewCipher(key) 
	if err != nil {
		record.Error("%v", err)
	}

	AEAD, err := cipher.NewGCM(aesBlock)
	if err != nil {
		record.Error("%v", err)
	}

	GCMCipherWriter := crypter.NewGCMWriter(cipherFile, 64 * 1024, AEAD)

	crypter.GCMEncrypt(GCMCipherWriter, file)

}

func de() {

	if len(flag.Arg(1)) == 0 {
		record.Error("%v", errors.New("input file missing"))
	}
	inputFile := flag.Arg(1)

	if len(flag.Arg(2)) != 0 {
		outputFile = flag.Arg(2)
	} else {
		outputFile = inputFile + ".dec"
	}

	key, err := crypter.GetUserKey()
	if err != nil {
		record.Error("%v", err)
		os.Exit(1)
	}

	file, err := os.Open(inputFile)
	if err != nil {
		record.Error("%v", err)
	}

	plainTextFile, err := os.Create(outputFile)
	if err != nil {
		record.Error("%v", err)
	}

	aesBlock, err := aes.NewCipher(key) 
	if err != nil {
		record.Error("%v", err)
	}

	AEAD, err := cipher.NewGCM(aesBlock)
	if err != nil {
		record.Error("%v", err)
	}

	GCMCipherWriter := crypter.NewGCMWriter(plainTextFile, 64 * 1024, AEAD)

	crypter.GCMDecrypt(GCMCipherWriter, file)

}

func setKey() {
	err := crypter.SetUserKey(key)
	if err != nil {
		record.Error("%v", err)
		os.Exit(1)
	}
}

func genKey() {

	seed := flag.Arg(2)

	length, err := strconv.ParseInt(flag.Arg(1), 10, 64)
	if err != nil {
		record.Error("%v", err)
		os.Exit(1)
	}

	key, err := crypter.GenKey(int(length), seed)
	if err != nil {
		record.Error("%v", err)
		os.Exit(1)
	}

	keyHexString := hex.EncodeToString(key)

	record.Info("your key: %v", keyHexString)

	err = crypter.SetUserKey(keyHexString)
	
	if err != nil {
		record.Error("%v", err)
		os.Exit(1)
	}
}

func getHex() {
	inputFile := flag.Arg(1)
	file, _ := os.ReadFile(inputFile)
	record.Info("%v", hex.EncodeToString(file))
}