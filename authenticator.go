package gobo

import (
	"encoding/json"
    "encoding/base64"
    "crypto/hmac"
    "crypto/sha256"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
    "strings"
)

// Authenticator结构体实现了微博应用授权功能
type Authenticator struct {
	redirectUri  string
	clientId     string
	clientSecret string
    accessToken  string
    refreshToken string
	httpClient   *http.Client
}

func NewAuthenticator(clientId string, clientSecret string, args ...string) *Authenticator {
    a := new(Authenticator)
    a.clientId = clientId
    a.clientSecret = clientSecret
    if len(args) >= 1 {
        a.accessToken = args[0]
    }
    if len(args) >= 2 {
        a.refreshToken = args[1]
    }
    a.httpClient = new(http.Client)
    return a
}


func (a *Authenticator) GetAuthorizeURL(redirect_uri string, args ...string) string {
	queries := url.Values{}

	queries.Add("redirect_uri", redirect_uri)
    queries.Add("client_id", a.clientId)
    if len(args) >= 1 {
        queries.Add("response_type", args[0])
    } else {
        queries.Add("response_type", "code")
    }
    if len(args) >= 2 {
        queries.Add("state", args[1])
    }
    if len(args) >= 3 {
        queries.Add("display", args[2])
    }

    return fmt.Sprintf("%s/oauth2/authorize?%s", ApiDomain, queries.Encode())

}

func (a *Authenticator) GetAccessToken(grant_type string, args ...string) (*AccessToken, error) {
    queries := url.Values{}

    switch(grant_type) {
    case "code":
        queries.Add("grant_type", "authorization_code")
        if len(args) >= 1 {
            queries.Add("code", args[0])
        }
        if len(args) >= 2 {
            queries.Add("redirect_uri", args[1])
        }
    case "token":
        queries.Add("grant_type", "refresh_token")
        if len(args) >= 1 {
            queries.Add("refresh_token", args[0])
        }
    case "password":
        queries.Add("grant_type", "password")
        if len(args) >= 1 {
            queries.Add("username", args[0])
        }
        if len(args) >= 2 {
            queries.Add("password", args[1])
        }
    default:
        return nil, &ErrorString{"grant_type参数错误"}
    }

    token := new(AccessToken)
    err := a.sendPostHttpRequest("oauth2/access_token", queries, token)
    if err != nil {
        return nil, err
    }
    return token, nil
}

// 得到访问令牌对应的信息
func (a *Authenticator) GetTokenInfo(token string) (*AccessTokenInfo, error) {
	// 生成请求URI
	queries := url.Values{}
	queries.Add("access_token", token)

    info := new(AccessTokenInfo)
	// 发送请求
	err := a.sendPostHttpRequest("oauth2/get_token_info", queries, info)
    if err != nil {
        return nil, err
    }
	return info, nil
}

// 解除访问令牌的授权
func (a *Authenticator) RevokeOAuth2(token string) error {

	// 生成请求URI
	queries := url.Values{}
	queries.Add("access_token", token)

	// 发送请求
	type Result struct {
		Result string
	}
	var result Result
	err := a.sendPostHttpRequest("oauth2/revokeoauth2", queries, &result)
	return err
}

func (a *Authenticator) ParseSignedRequest(signed_request string) (*SignedRequest, error) {
    res := strings.SplitN(signed_request, ".", 2)
    sig := a.base64Decode(res[0])
    sr := new(SignedRequest)
    err := json.Unmarshal(a.base64Decode(res[1]), sr)
    if err != nil {
        return nil, err
    }
    if strings.ToUpper(sr.Algorithm) != "HMAC-SHA256" {
        return nil, &ErrorString{"algorithm should be HMAC_SHA256"}
    }
    mac := hmac.New(sha256.New, []byte(a.clientSecret))
    mac.Write([]byte(res[1]))
    if hmac.Equal(sig, mac.Sum(nil)) {
        return sr, nil
    }
    return nil, &ErrorString{"signed check wrong"}
}

func (a *Authenticator) base64Decode(str string) []byte {
    s := strings.Replace(strings.Replace(str + strings.Repeat("=", 4 - len(str) % 4), "-", "+", -1), "_", "/", -1)
    data, err := base64.StdEncoding.DecodeString(s)
    if err != nil {
        return nil
    }
    return data
}

func (auth *Authenticator) sendPostHttpRequest(apiName string, queries url.Values, response interface{}) error {
	// 生成请求URI
	requestUri := fmt.Sprintf("%s/%s", ApiDomain, apiName)

	// 发送POST Form请求
	resp, err := auth.httpClient.PostForm(requestUri, queries)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// 解析返回内容
	bytes, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode == 200 {
		err := json.Unmarshal(bytes, &response)
		if err != nil {
			return err
		}
	} else {
		var weiboErr WeiboError
		err := json.Unmarshal(bytes, &weiboErr)
		if err != nil {
			return err
		}
		return weiboErr
	}
	return nil
}
