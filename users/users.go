package users

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"
)
const (
	Host     = "https://openapi.tuyain.com"
	ClientID = "hkurt3tgtmyj7ghevd39"
	Secret   = "8feedecdd12f41f487d89d1c5f380e6a"
	DeviceID = ""
)

var  Token string

type UserRegister struct {
	Name string `json:"username"`
	Password string `json:"password"`
	CountryCode string `json:"country_code"`
}

func RegisterUsers() {
	// reqBody := UserRegister{
	// 	"Rohit Test User",
	// 	"596dd1e610d5c82e6bb257d1b8c6171366ed6725fa7c4a894b0573346eaa8132",
	// 	"+91",
	// }

	

	method := "POST"
	url := "https://openapi.tuyain.com/v1.0/iot-02/users"

	// body,marErr := json.Marshal(&reqBody)
	body := []byte(``)
	// if marErr != nil {
	// 	fmt.Println(marErr)
	// }
	req, reqErr := http.NewRequest(method, url, bytes.NewReader(body))

	if reqErr != nil {
		fmt.Println(reqErr)
	}



	buildHeaders(req, body)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println(err)
		return
	}
	defer resp.Body.Close()
	bs, _ := ioutil.ReadAll(resp.Body)
	var ret  interface{}
	json.Unmarshal(bs, &ret)
	log.Println("GUser Response:", string(bs))
}

func GetUsers() {
	method := "GET"
	url := Host+"/v1.0/iot-02/users/bin1688816789313f5GX"
	body := []byte(``)

	req,_ := http.NewRequest(method, url, bytes.NewReader(body))

	buildHeaders(req, body)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println(err)
		return
	}
	defer resp.Body.Close()
	bs, _ := ioutil.ReadAll(resp.Body)
	var ret  interface{}
	json.Unmarshal(bs, &ret)
	log.Println("Single User Response:", string(bs))
}

func DeleteDevice() {
	method := "DELETE"
	url := Host + "/v2.0/cloud/thing/vdevo168862586510828"
	body := []byte(``)

	req, _ := http.NewRequest(method, url, bytes.NewReader(body))

	buildHeaders(req, body)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println(err)
		return
	}
	defer resp.Body.Close()
	bs, _ := ioutil.ReadAll(resp.Body)
	var ret  interface{}
	json.Unmarshal(bs, &ret)
	log.Println("Delete Device Response:", string(bs))
}

func RegisterDevice() {
	method := "POST"
	url := Host + "/v1.0/iot-03/3rdcloud/devices/A180072108301212/register"

	bodyJSON := struct{
		DeviceName string `json:"device_name"`
		ProductID string `json:"product_id"`
		}{
			"RohitFirstDevice",
			"xkdrfiieu5wbhmbq",
		}
	
	body,_ := json.Marshal(bodyJSON)

	req, _ := http.NewRequest(method, url, bytes.NewReader(body))

	buildHeaders(req, body)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println(err)
		return
	}
	defer resp.Body.Close()
	bs, _ := ioutil.ReadAll(resp.Body)
	var ret  interface{}
	json.Unmarshal(bs, &ret)
	log.Println("Register Device Response:", string(bs))
}

func buildHeaders(req *http.Request, body []byte) {


	req.Header["client_id"] = []string{ClientID}
	req.Header["sign_method"] = []string{"HMAC-SHA256"}
	req.Header["mode"] = []string{"cors"}
	req.Header["Content-Type"] = []string{"application/json"}

	ts := fmt.Sprint(time.Now().UnixNano() / 1e6)

	req.Header["t"] = []string{ts}

	// if Token != "" {
	// 	//req.Header.Add("access_token", Token)
	// 	req.Header["access_token"] = []string{Token}
	// }

	req.Header["access_token"] = []string{Token}
	req.Header["Signature-Headers"] = []string{"client_id:sign_method:mode:Content-Type:t:access_token"}
	sign := buildSigns(req, body, ts)
	req.Header["sign"] = []string{sign}
}

func buildSigns(req *http.Request, body []byte, t string) string {
	headers := getHeaderStrs(req)
	urlStr := getUrlStrs(req)
	contentSha256 := Sha256Algo(body)
	stringToSign := req.Method + "\n" + contentSha256 + "\n" + headers + "\n" + urlStr
	signStr := ClientID + Token + t + stringToSign
	sign := strings.ToUpper(HmacSha256Algo(signStr, Secret))
	return sign
}

func Sha256Algo(data []byte) string {
	sha256Contain := sha256.New()
	sha256Contain.Write(data)
	return hex.EncodeToString(sha256Contain.Sum(nil))
}

func getUrlStrs(req *http.Request) string {
	url := req.URL.Path
	keys := make([]string, 0, 10)

	query := req.URL.Query()
	for key, _ := range query {
		keys = append(keys, key)
	}
	if len(keys) > 0 {
		url += "?"
		sort.Strings(keys)
		for _, keyName := range keys {
			value := query.Get(keyName)
			url += keyName + "=" + value + "&"
		}
	}

	if url[len(url)-1] == '&' {
		url = url[:len(url)-1]
	}
	return url
}

func getHeaderStrs(req *http.Request) string {

	signHeaderKeys := req.Header.Get("Signature-Headers")
	if signHeaderKeys == "" {
		return ""
	}
	keys := strings.Split(signHeaderKeys, ":")
	headers := ""

	for _, key := range keys {
		val := req.Header[key]

		if len(val) > 0 {
			headers += key + ":" + val[0] + "\n"
		}else{
			headers += key + ":" + "" +"\n"
		}
	}

	fmt.Println("Returing a headers from req : ", headers)
	return headers
}

func HmacSha256Algo(message string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	sha := hex.EncodeToString(h.Sum(nil))
	return sha
}