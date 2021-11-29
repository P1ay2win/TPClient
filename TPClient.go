package main

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	Trace    *log.Logger
	Info     *log.Logger
	Warning  *log.Logger
	Error    *log.Logger
	clientip string
	nasip    string
	mac      string
	secret   = "Eshore!@#"
	version  = "214"
	jar, _   = cookiejar.New(nil)
	client   = &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
)

var (
	username  string
	password  string
	dpassword string
)

const (
	CTJSON       = "application/json"
	CTURL        = "application/x-www-form-urlencoded"
	DEVICEPORTAL = "http://172.17.18.2:8080"
	WEBPORTAL    = "http://enet.10000.gd.cn:10001"
)

type Json struct {
	Username      string `json:"username"`
	Password      string `json:"password,omitempty"`
	Clientip      string `json:"clientip"`
	Nasip         string `json:"nasip"`
	Version       string `json:"version"`
	Mac           string `json:"mac"`
	Iswifi        string `json:"iswifi,omitempty"`
	Timestamp     string `json:"timestamp"`
	Authenticator string `json:"authenticator"`
}

func main() {
	flag.Parse()
	if username == "" || password == "" {
		usage()
	}

	if !isDeviceLogin() {
		deviceLogin()
		waitForReconnect()
	}
	if !isLogin() {
		login()
	}
}

func init() {
	Trace = log.New(ioutil.Discard, "TRACE: ", log.Ldate|log.Ltime|log.Lshortfile)

	Info = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)

	Warning = log.New(os.Stdout, "WARNING: ", log.Ldate|log.Ltime|log.Lshortfile)

	Error = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)

	flag.StringVar(&username, "u", "", "set `username`.")
	flag.StringVar(&password, "p", "", "set network portal `password`.")
	flag.StringVar(&dpassword, "d", "123456", "set device portal `password`, this is optional.")
	flag.StringVar(&mac, "m", "", "set mac `address`, this is optional. If you connet by your router, this must be the mac address of your router.")
	flag.Usage = usage
}

func usage() {
	fmt.Print(`                    ___         ___                                     ___           ___
                   /\  \       /\__\                                   /\__\         /\  \
      ___         /::\  \     /:/  /                      ___         /:/ _/_        \:\  \         ___
     /\__\       /:/\:\__\   /:/  /                      /\__\       /:/ /\__\        \:\  \       /\__\
    /:/  /      /:/ /:/  /  /:/  /  ___   ___     ___   /:/__/      /:/ /:/ _/_   _____\:\  \     /:/  /
   /:/__/      /:/_/:/  /  /:/__/  /\__\ /\  \   /\__\ /::\  \     /:/_/:/ /\__\ /::::::::\__\   /:/__/
  /::\  \      \:\/:/  /   \:\  \ /:/  / \:\  \ /:/  / \/\:\  \__  \:\/:/ /:/  / \:\~~\~~\/__/  /::\  \
 /:/\:\  \      \::/__/     \:\  /:/  /   \:\  /:/  /   ~~\:\/\__\  \::/_/:/  /   \:\  \       /:/\:\  \
 \/__\:\  \      \:\  \      \:\/:/  /     \:\/:/  /       \::/  /   \:\/:/  /     \:\  \      \/__\:\  \
      \:\__\      \:\__\      \::/  /       \::/  /        /:/  /     \::/  /       \:\__\          \:\__\
       \/__/       \/__/       \/__/         \/__/         \/__/       \/__/         \/__/           \/__/
TPClient version: TPClinet/1.0.3
Usage: TPClient -u <username> -p <password> [-d password] [-m address]

Options:
`)
	flag.PrintDefaults()
	os.Exit(0)
}

func checkNetworkStatus() bool {
	conn, err := net.DialTimeout("tcp", "114.114.114.114:53", 5*time.Second)
	for err == nil {
		conn.Close()
		time.Sleep(10 * time.Second)
		conn, err = net.DialTimeout("tcp", "114.114.114.114:53", 5*time.Second)
	}
	return true
}

func isDeviceLogin() bool {
	conn, err := net.DialTimeout("tcp", "enet.10000.gd.cn:10001", 2*time.Second)
	if err == nil {
		conn.Close()
		Info.Println("Device is logged in.")
		return true
	}
	Info.Println("Device ready to log in.")
	return false
}

func deviceLogin() {

	resp, err := http.Get(DEVICEPORTAL + "/byod/index.xhtml")
	if err != nil {
		Error.Println("Cannot connect to drive portal web site!Make sure you are connected to the campus network.")
		os.Exit(1)
	}

	cookie := resp.Cookies()
	u, _ := url.Parse(DEVICEPORTAL)
	jar.SetCookies(u, cookie)

	body, _ := ioutil.ReadAll(resp.Body)
	r, _ := regexp.Compile("ViewState\" value=\"(.*?)\"")
	vs := r.FindStringSubmatch(string(body))

	resp, _ = client.Post(DEVICEPORTAL+"/byod/index.xhtml", CTURL, strings.NewReader("wlannasid=&usermac=&userurl=&userip=&ssid=&btn=&j_id_3_SUBMIT=1&javax.faces.ViewState="+url.QueryEscape(vs[1])))
	login, _ := resp.Location()
	resp, _ = client.Get(login.String())
	body, _ = ioutil.ReadAll(resp.Body)
	vs = r.FindStringSubmatch(string(body))

	resp, _ = client.Post(login.String(), CTURL, strings.NewReader("javax.faces.partial.ajax=true&javax.faces.source=mainForm%3Aj_id_r&javax.faces.partial.execute=mainForm&javax.faces.partial.render=mainForm%3Aerror+mainForm%3AforResetPwd&mainForm%3Aj_id_r=mainForm%3Aj_id_r&mainForm%3AforResetPwd=admin&userName=&userPwd=&userDynamicPwd=&userDynamicPwdd=&serviceType=&mainForm%3AuserNameLogin="+url.QueryEscape(username)+"&mainForm%3AserviceSuffixLogin=&mainForm%3ApasswordLogin="+url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(dpassword)))+"&mainForm%3AuserDynamicPwd=&mainForm%3AuserDynamicPwdd=&mainForm_SUBMIT=1&javax.faces.ViewState="+url.QueryEscape(string(vs[1]))))
	body, _ = ioutil.ReadAll(resp.Body)

	if strings.Contains(string(body), "summary:\"失败\"") {
		r, _ := regexp.Compile("summary:\"失败\",detail:\"(.*?)\"")
		msg := r.FindStringSubmatch(string(body))

		if strings.Contains(msg[1], "E63032") {
			Error.Println("Password error. " + msg[1])
		}else if strings.Contains(msg[1], "E63018") {
			Error.Println("Username error." + msg[1])
		}else {
			Error.Println("Device login failed. " + msg[1])
		}
		os.Exit(1)
	}
	Info.Println("Device login successful.")
}

func waitForReconnect() {
	conn, err := net.DialTimeout("tcp", "enet.10000.gd.cn:10001", 2*time.Second)
	for err != nil {
		conn, err = net.DialTimeout("tcp", "enet.10000.gd.cn:10001", 2*time.Second)
	}
	conn.Close()
}

func isLogin() bool {
	resp, _ := client.Get("http://www.qq.com/")
	location, _ := resp.Location()
	if strings.Contains(location.String(), "www.qq.com") {
		Info.Println("Already logged into the campus network")
		return true
	}
	Info.Println("Ready to log into the campus network.")
	return false
}

func login() {
	resp, _ := client.Get("http://www.qq.com")
	location, _ := resp.Location()
	resp, _ = client.Get(location.String())
	jar.SetCookies(location, resp.Cookies())
	r, _ := regexp.Compile("wlanuserip=(.*?)&wlanacip=(.*)")
	ip := r.FindStringSubmatch(location.String())
	clientip = ip[1]
	nasip = ip[2]

	getMacAddr(clientip)
	code := getVerifyCode()
	doLogin(code)
}

func getMacAddr(wwwIp string) string {
	if mac != "" {
		mac = strings.ReplaceAll(mac, ":", "-")
		Info.Println("MAC address:" + mac + ".")
		return mac
	}

	ifs, _ := net.Interfaces()
	for _, ifInfo := range ifs {
		ips, _ := ifInfo.Addrs()
		for _, ip := range ips {
			if strings.Contains(ip.String(), wwwIp) {
				mac = strings.ReplaceAll(ifInfo.HardwareAddr.String(), ":", "-")
				Info.Println("MAC address:" + mac + ".")
				return mac
			}
		}
	}
	return ""
}

func paramInit() *Json {
	jsonObject := &Json{}
	jsonObject.Username = username
	jsonObject.Clientip = clientip
	jsonObject.Nasip = nasip
	jsonObject.Mac = mac
	return jsonObject
}

func getVerifyCode() string {
	timestamp := strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
	authenticator := fmt.Sprintf("%X", md5.Sum([]byte(version+clientip+nasip+mac+timestamp+secret)))
	jsonObject := paramInit()
	jsonObject.Version = version
	jsonObject.Timestamp = timestamp
	jsonObject.Authenticator = authenticator
	data, _ := json.Marshal(jsonObject)

	resp, _ := client.Post(WEBPORTAL+"/client/vchallenge", CTJSON, strings.NewReader(string(data)))
	body, _ := ioutil.ReadAll(resp.Body)
	r, _ := regexp.Compile("\"challenge\":\"(.*?)\"")
	code := r.FindStringSubmatch(string(body))
	Info.Println("Verify Code:" + code[1] + ".")
	return code[1]
}

func doLogin(code string) {
	timestamp := strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
	authenticator := fmt.Sprintf("%X", md5.Sum([]byte(clientip+nasip+mac+timestamp+code+secret)))
	jsonObject := paramInit()
	jsonObject.Password = password
	jsonObject.Iswifi = "4060"
	jsonObject.Timestamp = timestamp
	jsonObject.Authenticator = authenticator
	data, _ := json.Marshal(jsonObject)

	resp, _ := client.Post(WEBPORTAL+"/client/login", CTJSON, strings.NewReader(string(data)))
	body, _ := ioutil.ReadAll(resp.Body)
	r, _ := regexp.Compile("\"rescode\":\"(.*?)\"")
	result := r.FindStringSubmatch(string(body))
	if !strings.Contains(result[1], "0") {
		r, _ = regexp.Compile("\"resinfo\":\"(.*?)\"")
		msg := r.FindStringSubmatch(string(body))
		Error.Println("Login Error." + msg[1])
		os.Exit(1)
	}
	Info.Println("Login successful.")
}

func doLogout() {
	timestamp := strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
	authenticator := fmt.Sprintf("%X", md5.Sum([]byte(clientip+nasip+mac+timestamp+secret)))
	jsonObject := paramInit()
	jsonObject.Timestamp = timestamp
	jsonObject.Authenticator = authenticator
	data, _ := json.Marshal(jsonObject)

	resp, _ := client.Post(WEBPORTAL+"/client/logout", CTJSON, strings.NewReader(string(data)))
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
	Info.Println("Logout successful.")
}

func keepAlive() {
	timestamp := strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
	authenticator := fmt.Sprintf("%X", md5.Sum([]byte(clientip+nasip+mac+timestamp+secret)))
	param := fmt.Sprintf("username=%s&clientip=%s&nasip=%s&mac=%s&timestamp=%s&authenticator=%s", username, clientip, nasip, mac, timestamp, authenticator)
	resp, _ := client.Post(WEBPORTAL+"/hbservice/client/active", CTURL, strings.NewReader(param))

	body, _ := ioutil.ReadAll(resp.Body)
	Info.Println(string(body))
}
