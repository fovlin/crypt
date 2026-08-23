package crypter

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
)

type GCMCipherWriter struct {
	Writer io.Writer
	BlockSize int
	AEAD cipher.AEAD
}

func NewGCMWriter(Writer io.Writer, BlockSize int, AEAD cipher.AEAD) GCMCipherWriter {
	var GCMCrypter GCMCipherWriter = GCMCipherWriter{
		Writer,
		BlockSize,
		AEAD,
	}
	return GCMCrypter
}

func GCMEncrypt(GCMCipherWriter GCMCipherWriter,ioReader io.Reader) (err error) {

	Writer := GCMCipherWriter.Writer
	BlockSize := GCMCipherWriter.BlockSize
	AEAD := GCMCipherWriter.AEAD

	buf := make([]byte, BlockSize)
	for {

		readLength, err := io.ReadFull(ioReader, buf)
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

		_, err = Writer.Write(iv)
		if err != nil {
			return err
		}

		cipherData := AEAD.Seal(nil, iv, buf[:readLength], nil)
		_, err = Writer.Write(cipherData)
		if err != nil {
			return err
		}

	}

	return nil

}


func GCMDecrypt(GCMCipherWriter GCMCipherWriter,ioReader io.Reader) (err error) {

	Writer := GCMCipherWriter.Writer
	BlockSize := GCMCipherWriter.BlockSize
	AEAD := GCMCipherWriter.AEAD

	buf := make([]byte, 12 + BlockSize + 16)
	for {

		readLength, err := io.ReadFull(ioReader, buf)
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

		data, err := AEAD.Open(nil, iv, buf[12:readLength], nil)
		if err != nil {
			return err
		}

		_, err = Writer.Write(data)
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
		return nil, errors.New("(config file error) \"key\" not found")
	}

	_, ok = keyData.(string)
	if !ok {
		return nil, errors.New("(config file error) \"key\"isn't a string")
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
		return errors.New(homeDir + " isn't a directory")
	}

	configFilePath := path.Join(homeDir, ".crypt.conf")

	configFileSata, err := os.Stat(configFilePath)
	if err != nil {
		os.WriteFile(configFilePath, nil, 0700)
	}
	if err == nil && configFileSata.IsDir() {
		return errors.New("config file \"" + configFilePath + "\" is a directory")
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
		return nil, errors.New("only supports 16, 24, 32 bits length")
	}

	if seed != "" {
		if length != 32 {
			return nil, errors.New("seed mode only supports 32 bits length")
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