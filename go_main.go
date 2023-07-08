package main

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

	"github.com/aniket0951.com/users"
)

const (
	Host     = "https://openapi.tuyain.com"
	ClientID = "hkurt3tgtmyj7ghevd39"
	Secret   = "8feedecdd12f41f487d89d1c5f380e6a"
	DeviceID = ""
)

var (
	Token string
)

type TokenResponse struct {
	Result struct {
		AccessToken  string `json:"access_token"`
		ExpireTime   int    `json:"expire_time"`
		RefreshToken string `json:"refresh_token"`
		UID          string `json:"uid"`
	} `json:"result"`
	Success bool  `json:"success"`
	T       int64 `json:"t"`
}

func main() {

	GetToken()
	//GetUserPermissions()
	users.Token = Token
	//users.RegisterUsers()
	//users.GetUsers()
	//users.DeleteDevice()
	users.RegisterDevice()
	//GetDevice(DeviceID)
}

func GetToken() {
	method := "GET"
	body := []byte(``)
	req, _ := http.NewRequest(method, Host+"/v1.0/token?grant_type=1", bytes.NewReader(body))

	buildHeader(req, body)
	fmt.Println("Request : ", req.Header)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println(err)
		return
	}
	defer resp.Body.Close()
	bs, _ := ioutil.ReadAll(resp.Body)
	ret := TokenResponse{}
	json.Unmarshal(bs, &ret)
	log.Println("Get Tooken resp:", string(bs))

	if v := ret.Result.AccessToken; v != "" {
		Token = v
	}
}

// get user permissions

func GetUserPermissions() {
	method := "GET"
	// mp := map[string]string{}
	// mp["device_name"] = "RohitFirstDevice"
	// mp["product_id"] = "xkdrfiieu5wbhmbq"

	body := []byte(``)

	req, reqErr := http.NewRequest(method, Host+"/v1.0/iot-02/users/bay1687262453468f92G/permissions", bytes.NewReader(body))

	fmt.Println("Request Error : ", reqErr)

	buildHeader(req, body)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println(err)
		return
	}

	defer resp.Body.Close()
	bs, _ := ioutil.ReadAll(resp.Body)
	ret := TokenResponse{}
	json.Unmarshal(bs, &ret)
	log.Println("permission resp:", string(bs))

	if v := ret.Result.AccessToken; v != "" {
		Token = v
	}
}

func GetDevice(deviceId string) {
	method := "GET"
	body := []byte(``)
	req, _ := http.NewRequest(method, Host+"/v1.0/devices/"+deviceId, bytes.NewReader(body))

	buildHeader(req, body)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println(err)
		return
	}
	defer resp.Body.Close()
	bs, _ := ioutil.ReadAll(resp.Body)
	log.Println("resp:", string(bs))
}

func buildHeader(req *http.Request, body []byte) {


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
	sign := buildSign(req, body, ts)
	req.Header["sign"] = []string{sign}

}

func buildSign(req *http.Request, body []byte, t string) string {
	headers := getHeaderStr(req)
	urlStr := getUrlStr(req)
	contentSha256 := Sha256(body)
	stringToSign := req.Method + "\n" + contentSha256 + "\n" + headers + "\n" + urlStr
	signStr := ClientID + Token + t + stringToSign
	sign := strings.ToUpper(HmacSha256(signStr, Secret))
	return sign
}

func Sha256(data []byte) string {
	sha256Contain := sha256.New()
	sha256Contain.Write(data)
	return hex.EncodeToString(sha256Contain.Sum(nil))
}

func getUrlStr(req *http.Request) string {
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

func getHeaderStr(req *http.Request) string {

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

	return headers
}

func HmacSha256(message string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	sha := hex.EncodeToString(h.Sum(nil))
	return sha
}
