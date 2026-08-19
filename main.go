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
	// record.Info("Using key: %v", hex.EncodeToString(key))

	err = crypter.GCMEncrypt(inputFile, outputFile, key)
	if err != nil {
		record.Error("%v", err)
		os.Exit(1)
	}

}

func de() {
	inputFile := flag.Arg(1)

	key, err := crypter.GetUserKey()
	if err != nil {
		record.Error("%v", err)
		os.Exit(1)
	}
	// record.Info("Using key: %v", hex.EncodeToString(key))

	err = crypter.GCMDecrypt(inputFile, outputFile,key)
	if err != nil {
		record.Error("%v", err)
		os.Exit(1)
	}
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