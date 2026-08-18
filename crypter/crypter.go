package crypter

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	// "crypto/rand"
	"os"
	"path"
	"strings"
)

func Encrypt(inputFile string, outputFile string, key []byte, iv []byte) error {
	
	if inputFile == "" {
		return errors.New("Input file name is missing")
	}

	if outputFile == "" {
		outputFile = inputFile + ".enc"
	}

	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	fileReader, err := os.Open(inputFile)
	if err != nil {
		return err
	}

	defer fileReader.Close()

	stream := cipher.NewCTR(cipherBlock, iv)
	encFile, err := os.Create(outputFile)
	if err != nil {
		return err
	}

	var cipherStreamWriter cipher.StreamWriter
	cipherStreamWriter.S = stream
	cipherStreamWriter.W = encFile
	cipherStreamWriter.Err = nil

	buf := bytes.NewBuffer(iv)

	_, err = io.Copy(encFile, buf)
	if err != nil {
		return err
	}
	
	_, err = io.Copy(cipherStreamWriter, fileReader)
	if err != nil {
		return err
	}

	return nil

}


func Decrypt(inputFile string, outputFile string, key []byte, iv []byte) error {

	if inputFile == "" {
		return errors.New("Input file name is missing")
	}

	if outputFile == "" {
		if strings.HasSuffix(inputFile, ".enc") {
			outputFile, _ = strings.CutSuffix(inputFile, ".enc")
		} else {
			outputFile = inputFile + ".dec"
		}
	}

	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	fileReader, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer fileReader.Close()

	stream := cipher.NewCTR(cipherBlock, iv)
	decFile, err := os.Create(outputFile)
	if err != nil {
		return err
	}

	var cipherStreamReader cipher.StreamReader
	cipherStreamReader.S = stream
	cipherStreamReader.R = fileReader

	fileReader.Read(iv)

	io.Copy(decFile, cipherStreamReader)

	return nil
}


func GetUserKey() (key []byte ,err error) {

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	configFilePath := path.Join(homeDir, ".config", "crypt.conf")

	configFileData, err := os.ReadFile(configFilePath)
	if err != nil {
		return nil, err
	}

	var configData map[string]any

	err = json.Unmarshal(configFileData, &configData)
	if err != nil {
		return nil, err
	}

	keyData, ok := configData["key"]
	if !ok {
		return nil, errors.New("(Config file error) \"key\" not found")
	}

	_, ok = keyData.(string)
	if !ok {
		return nil, errors.New("(Config file error) \"key\"isn't a string")
	}
	key, err = hex.DecodeString(keyData.(string))

	return key, nil

}

func GetFileIv(inputFile string) (iv []byte, err error) {

	file, err := os.Open(inputFile)
	if err != nil {
		return nil, err
	}

	iv = make([]byte, 16)

	_, err = io.ReadFull(file, iv)
	if err != nil {
		return nil, err
	}

	return iv, nil
}

func SetUserKey(key string) error {

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	configFilePath := path.Join(homeDir, ".config", "crypt.conf")

	_, err = os.Stat(configFilePath)
	if err != nil {
		err = os.MkdirAll(path.Join(homeDir, ".config"), 0766)
		if err != nil {
			return err
		}
	}

	configFileData, err := os.ReadFile(configFilePath)
	if err != nil {
		return err
	}

	var userConfig map[string]any

	err = json.Unmarshal(configFileData, &userConfig)
	if err != nil {
		return err
	}

	userConfig["key"] = key

	configData, err := json.MarshalIndent(userConfig, "", "  ")
	if err != nil {
		return err
	}

	err = os.WriteFile(configFilePath, configData, 0766)
	if err != nil {
		return err
	}

	return nil

}

func GenKey(length int, seed string) (key []byte,err error) {

	if length != 16 && length != 24 && length != 32 {
		return nil, errors.New("Only supports 16, 24, 32 bits length")
	}

	if seed != "" {
		if length != 32 {
			return nil, errors.New("Seed mode only supports 32 bits length")
		}
		hash := sha256.New()
		hash.Write([]byte(seed))
		key := hash.Sum(nil)
		return key, nil
	}

	key = make([]byte, length)
	_, err = io.ReadFull(rand.Reader, key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func GenIv() (iv []byte,err error) {

	iv = make([]byte, 16)
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, err
	}
	return iv, nil

}