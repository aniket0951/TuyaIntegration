package helper

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"sort"
	"strings"
	"time"
)

func APICallCURL() {

  url := "https://openapi.tuyain.com/v1.0/token?grant_type=1"
  method := "GET"
  reqbody := []byte(``)
  client := &http.Client {
  }
  req, err := http.NewRequest(method, url, nil)

  if err != nil {
    fmt.Println(err)
    return
  }
  buildHeaders(req, reqbody)

  res, err := client.Do(req)
  if err != nil {
    fmt.Println(err)
    return
  }
  defer res.Body.Close()

  body, err := ioutil.ReadAll(res.Body)
  if err != nil {
    fmt.Println(err)
    return
  }
  fmt.Println(string(body))
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