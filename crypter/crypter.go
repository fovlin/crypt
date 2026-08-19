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
	"os"
	"path"
	"strings"
)

func CTREncrypt(inputFile string, outputFile string, key []byte, iv []byte) error {
	
	if inputFile == "" {
		return errors.New("Input file name is missing")
	}

	if outputFile == "" {
		outputFile = inputFile + ".enc"
	}

	if _, err := os.Stat(outputFile); !os.IsNotExist(err) {
		return errors.New("Output file \"" + outputFile + "\" existed")
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


func CTRDecrypt(inputFile string, outputFile string, key []byte, iv []byte) error {

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

	if _, err := os.Stat(outputFile); !os.IsNotExist(err) {
		return errors.New("Output file \"" + outputFile + "\" existed")
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

func GCMEncrypt(inputFile string, outputFile string, key []byte) (err error) {

	file, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	if outputFile == "" {
		outputFile = inputFile + ".enc"
	}
	
	if _, err = os.Stat(outputFile); !os.IsNotExist(err) {
		return errors.New("Output file \"" + outputFile + "\" existed")
	}
	
	encFile, err := os.Create(outputFile)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	buf := make([]byte, 64 * 1024)
	for {

		readLength, err := io.ReadFull(file, buf)
		if err == io.EOF {
			break
		}
		if err != nil && err != io.ErrUnexpectedEOF {
			return err
		}

		iv, err := GenRandomData(12)
		if err != nil {
			return err
		}

		_, err = encFile.Write(iv)
		if err != nil {
			return err
		}

		cipherData := aesgcm.Seal(nil, iv, buf[:readLength], nil)
		_, err = encFile.Write(cipherData)
		if err != nil {
			return err
		}

	}

	return nil
}


func GCMDecrypt(inputFile string, outputFile string, key []byte) (err error) {

	file, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer file.Close()
	
	if outputFile == "" {
		if strings.HasSuffix(inputFile, ".enc") {
			outputFile, _ = strings.CutSuffix(inputFile, ".enc")
		} else {
			outputFile = inputFile + ".dec"
		}
	}

	if _, err = os.Stat(outputFile); !os.IsNotExist(err) {
		return errors.New("Output file \"" + outputFile + "\" existed")
	}
	

	decFile, err := os.Create(outputFile)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	
	buf := make([]byte, 12 + 64 * 1024 + 16)

	for {

		readLength, err := io.ReadFull(file, buf)
		if err == io.EOF {
			break
		}
		if err != nil && err != io.ErrUnexpectedEOF {
			return err
		}

		if readLength < 12 + 16 {
			return errors.New("damaged block")
		}

		iv := make([]byte, 12)
		copy(iv, buf[:12])

		data, err := aesgcm.Open(nil, iv, buf[12:readLength], nil)
		if err != nil {
			return err
		}

		_, err = decFile.Write(data)
		if err != nil {
			return err
		}

		clear(iv)
	}

	return nil
}

func GetUserKey() (key []byte ,err error) {

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	configFilePath := path.Join(homeDir, ".crypt.conf")

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

func SetUserKey(key string) error {

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	homeDirStat, err := os.Stat(homeDir)
	if os.IsNotExist(err) {
		err = os.MkdirAll(path.Join(homeDir), 0766)
		if err != nil {
			return err
		}
		homeDirStat, err = os.Stat(homeDir)
		if err != nil {
			return err
		}
	} else if !os.IsNotExist(err) && err != nil {
		return err
	}

	if !homeDirStat.IsDir() {
		return errors.New("user home path isn't a directory")
	}

	configFilePath := path.Join(homeDir, ".crypt.conf")

	configFileSata, err := os.Stat(configFilePath)
	if err != nil {
		os.WriteFile(configFilePath, nil, 0700)
	}
	if err == nil && configFileSata.IsDir() {
		return errors.New("Config file \"" + configFilePath + "\" is a directory")
	}

	configFileData, err := os.ReadFile(configFilePath)
	if err != nil {
		return err
	}

	userConfig := make(map[string]any)

	_ = json.Unmarshal(configFileData, &userConfig)

	userConfig["key"] = key

	configData, err := json.MarshalIndent(userConfig, "", "  ")
	if err != nil {
		return err
	}

	err = os.WriteFile(configFilePath, configData, 0700)
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

func GenRandomData(length int) (iv []byte, err error) {

	iv = make([]byte, length)
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, err
	}
	return iv, nil

}