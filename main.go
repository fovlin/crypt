package main

import (
	"encoding/hex"
	"flag"
	"os"
	"strconv"

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

	flag.StringVar(&outputFile, "o", "", "Out file")
	flag.StringVar(&key, "k", "", "Input file")
	flag.StringVar(&iv, "i", "", "Input file")
	flag.Parse()
	
	command := flag.Arg(0)

	cmdMap = map[string]func() {

		"en": en,

		"de": de,

		"setkey": setKey,

		"genkey": genKey,
		"gethex": getHex,

	}

	function, ok := cmdMap[command]
	if !ok {
		record.Error("Command not found")
		os.Exit(1)
	}

	function()
}

func en() {
	inputFile := flag.Arg(1)

	key, err := crypter.GetUserKey()
	if err != nil {
		record.Error("%v", err)
		os.Exit(1)
	}
	iv, err := crypter.GenIv()
	if err != nil {
		record.Error("%v", err)
		os.Exit(1)
	}

	err = crypter.Encrypt(inputFile, outputFile, key, iv)
	if err != nil {
		record.Error("%v", err)
		os.Exit(1)
	}

	record.Info("Used key: %v", hex.EncodeToString(key))
	record.Info("Used iv: %v", hex.EncodeToString(iv))

}

func de() {
	inputFile := flag.Arg(1)

	key, err := crypter.GetUserKey()
	if err != nil {
		record.Error("%v", err)
		os.Exit(1)
	}

	iv, err := crypter.GetFileIv(inputFile)
	if err != nil {
		record.Error("%v", err)
		os.Exit(1)
	}

	err = crypter.Decrypt(inputFile, outputFile,key, iv)
	if err != nil {
		record.Error("%v", err)
		os.Exit(1)
	}

	record.Info("Used key: %v", hex.EncodeToString(key))
	record.Info("Used iv: %v", hex.EncodeToString(iv))
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

	record.Info("Your key: %v", keyHexString)

	crypter.SetUserKey(keyHexString)

}

func getHex() {
	inputFile := flag.Arg(1)
	file, _ := os.ReadFile(inputFile)
	record.Info("%v", hex.EncodeToString(file))
}