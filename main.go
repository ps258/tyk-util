package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

const connectionTimeout time.Duration = 5 * time.Second

type tykConnection struct {
	client  *http.Client
	baseURL string
	secret  string
}

func tykClient(u string, s string) *tykConnection {
	return &tykConnection{
		client: &http.Client{
			Timeout: connectionTimeout,
		},
		baseURL: u,
		secret:  s,
	}
}

func (tc *tykConnection) fetchAPIs() (model.APIs, error) {
	req, err := http.NewRequest("GET", tc.baseURL+"/api/apis", nil)
	if err != nil {
		log.Fatal("Error reading request: ", err)
	}
	req.Header.Set("Authorization", tc.secret)
	resp, err := tc.client.do(req)
	if err != nil {
		log.Fatal("Error reading response: ", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("Error reading body: ", err)
	}
	fmt.Printf("%s\n", body)
}

func main() {
	dashboard := flag.String("d", "", "Dashboard host URL")
	gateway := flag.String("g", "", "Gateway URL")
	secret := flag.String("s", "", "Either dashboard credentials or the gateway secret")
	list := flag.Bool("l", false, "List rather than sence check")
	check := flag.Bool("c", false, "Sense check rather than list")
	apis := flag.Bool("a", false, "Check/list the defined APIs")
	users := flag.Bool("u", false, "Check/list the users")
	flag.Parse()
	if (*dashboard != "" && *gateway != "") || (*dashboard == "" && *gateway == "") {
		log.Fatal("Specify exactly one of dashboard(-d) or gateway(-g)")
	}
	if (*list && *check) || (!*list && !*check) {
		log.Fatal("Specify exactly one of list(-l) or check(-c)")
	}
	if *secret == "" {
		log.Fatal("Must provide a secret(-s)")
	}
	if (*apis && *users) || (!*apis && !*users) {
		log.Fatal("Specify exactly one of apis(-a) or users(-u)")
	}
}
