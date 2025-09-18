package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
	time "time"
)

const (
	// Set useGlobal to true if you are running a Global ROM (Non-China Mainland)
	useGlobal = false
	version   = "1.0 (Go)"

	signKey  = "10f29ff413c89c8de02349cb3eb9a5f510f29ff413c89c8de02349cb3eb9a5f5"
	dataPass = "20nr1aobv2xi8ax4"
	dataIV   = "0102030405060708"
)

var (
	apiURL string
)

func init() {
	if useGlobal {
		apiURL = "https://unlock.update.intl.miui.com/v1/"
	} else {
		apiURL = "https://unlock.update.miui.com/v1/"
	}
}

// logf provides formatted logging with timestamps.
func logf(format string, a ...interface{}) {
	log.Printf(format, a...)
}

// runAdbCommand executes a simple ADB command and logs its output.
func runAdbCommand(args ...string) {
	cmd := exec.Command("adb", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logf("Error running 'adb %s': %v, output: %s", strings.Join(args, " "), err, string(output))
	}
}

// findAdbDevice finds a single connected device. It panics if not exactly one device is found.
func findAdbDevice() string {
	for {
		cmd := exec.Command("adb", "devices")
		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Fatalf("Failed to run 'adb devices': %v", err)
		}

		lines := strings.Split(string(output), "\n")
		devices := []string{}
		for _, line := range lines[1:] { // Skip the first line "List of devices attached"
			if strings.HasSuffix(strings.TrimSpace(line), "device") {
				fields := strings.Fields(line)
				if len(fields) > 0 {
					devices = append(devices, fields[0])
				}
			}
		}

		switch len(devices) {
		case 0:
			logf("Waiting for device connection...")
		case 1:
			logf("Processing device %s...", devices[0])
			return devices[0]
		default:
			logf("Only one device is allowed, but found %d. Please disconnect others.", len(devices))
		}
		time.Sleep(2 * time.Second)
	}
}

// streamLogcat monitors logcat for the unlock request data.
func streamLogcat(serial string) (string, string, error) {
	logf("Finding BootLoader unlock bind request...")
	runAdbCommand("-s", serial, "shell", "am", "start", "-a", "android.settings.APPLICATION_DEVELOPMENT_SETTINGS")
	logf("* Now you can bind account in the developer options.")

	cmd := exec.Command("adb", "-s", serial, "logcat", "*:S", "CloudDeviceStatus:V")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", "", fmt.Errorf("failed to get stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return "", "", fmt.Errorf("failed to start logcat: %w", err)
	}
	defer cmd.Process.Kill()

	scanner := bufio.NewScanner(stdout)
	argsRegex := regexp.MustCompile(`args:(.*)`)
	headersRegex := regexp.MustCompile(`headers:(.*)`)

	var args, headers string
	done := make(chan struct{})

	go func() {
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "CloudDeviceStatus: args:") {
				if matches := argsRegex.FindStringSubmatch(line); len(matches) > 1 {
					args = strings.TrimSpace(matches[1])
					runAdbCommand("-s", serial, "shell", "svc", "data", "disable")
				}
			}
			if strings.Contains(line, "CloudDeviceStatus: headers:") {
				if matches := headersRegex.FindStringSubmatch(line); len(matches) > 1 {
					headers = strings.TrimSpace(matches[1])
					logf("Account bind request found! Let's block it.")
					close(done)
					return
				}
			}
		}
	}()

	select {
	case <-done:
		if args == "" || headers == "" {
			return "", "", fmt.Errorf("found headers but args are missing")
		}

		return args, headers, nil
	case <-time.After(60 * time.Second): // 60-second timeout
		return "", "", fmt.Errorf("timed out waiting for logcat output")
	}
}

// PKCS7Unpad removes PKCS7 padding.
func PKCS7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data is empty")
	}
	length := len(data)
	unpadding := int(data[length-1])
	if unpadding > length {
		return nil, fmt.Errorf("invalid padding")
	}
	return data[:(length - unpadding)], nil
}

// decryptData performs AES-128-CBC decryption.
func decryptData(encryptedData string) (string, error) {
	key := []byte(dataPass)
	iv := []byte(dataIV)
	decodedData, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", fmt.Errorf("base64 decode failed: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(decodedData))
	mode.CryptBlocks(decrypted, decodedData)
	unpadded, err := PKCS7Unpad(decrypted)
	if err != nil {
		return "", fmt.Errorf("unpadding failed: %w", err)
	}
	return string(unpadded), nil
}

// signData performs HMAC-SHA1 signing.
func signData(data string) string {
	key := []byte(signKey)
	toSign := "POST\n/v1/unlock/applyBind\ndata=" + data + "&sid=miui_sec_android"
	h := hmac.New(sha1.New, key)
	h.Write([]byte(toSign))
	return hex.EncodeToString(h.Sum(nil))
}

// sendPostRequest sends the final POST request to the Xiaomi server.
func sendPostRequest(data, sign, cookies string) (map[string]interface{}, error) {
	form := url.Values{}
	form.Set("data", data)
	form.Set("sid", "miui_sec_android")
	form.Set("sign", sign)

	req, err := http.NewRequest("POST", apiURL+"unlock/applyBind", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", cookies)
	req.Header.Set("User-Agent", "Xiaomi-HyperOS-BootLoader-Bypass")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse json response: %w. Body: %s", err, string(body))
	}
	return result, nil
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	logf("************************************")
	logf("* Xiaomi HyperOS BootLoader Bypass *")
	logf("* By NekoYuzu (Go Port)  Version %s *", version)
	logf("************************************")

	serial := findAdbDevice()
	runAdbCommand("-s", serial, "shell", "svc", "data", "enable")
	defer runAdbCommand("-s", serial, "shell", "svc", "data", "enable")

	args, headers, err := streamLogcat(serial)
	if err != nil {
		log.Fatalf("Error: %v. Please try again.", err)
	}

	logf("Refactoring parameters...")
	decryptedArgs, err := decryptData(args)
	if err != nil {
		log.Fatalf("Failed to decrypt args: %v", err)
	}

	var dataMap map[string]interface{}
	if err := json.Unmarshal([]byte(decryptedArgs), &dataMap); err != nil {
		log.Fatalf("Failed to parse decrypted args JSON: %v", err)
	}

	// This is the bypass logic
	if romVersion, ok := dataMap["rom_version"].(string); ok {
		dataMap["rom_version"] = strings.Replace(romVersion, "V816", "V14", 1)
	}

	modifiedDataBytes, err := json.Marshal(dataMap)
	if err != nil {
		log.Fatalf("Failed to marshal modified data: %v", err)
	}
	modifiedData := string(modifiedDataBytes)

	sign := signData(modifiedData)

	decryptedHeaders, err := decryptData(headers)
	if err != nil {
		log.Fatalf("Failed to decrypt headers: %v", err)
	}

	cookieRegex := regexp.MustCompile(`Cookie=\[(.*?)`)
	cookieMatches := cookieRegex.FindStringSubmatch(decryptedHeaders)
	if len(cookieMatches) < 2 {
		log.Fatalf("Could not find cookie in decrypted headers")
	}
	cookies := cookieMatches[1]

	logf("Sending POST request...")
	res, err := sendPostRequest(modifiedData, sign, cookies)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}

	code, _ := res["code"].(float64)
	desc, _ := res["descEN"].(string)

	switch int(code) {
	case 0:
		if data, ok := res["data"].(map[string]interface{}); ok {
			logf("Success! Target account: %v", data["userId"])
		}
		logf("Account bound successfully, wait time can be viewed in the unlock tool.")
	case 401:
		logf("Error: Account credentials have expired, re-login to your account in your phone. (401)")
	default:
		logf("An error occurred: %s (%d)", desc, int(code))
		logf("Full response: %v", res)
	}
}
