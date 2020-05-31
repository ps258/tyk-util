package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/TykTechnologies/tyk/apidef"
)

const connectionTimeout time.Duration = 5 * time.Second

// OrgAPIs contains the APIs for the while organisation
type OrgAPIs struct {
	Apis []struct {
		CreatedAt time.Time `json:"created_at"`
		APIModel  struct {
		} `json:"api_model"`
		APIDefinition   apidef.APIDefinition `json:"api_definition"`
		HookReferences  []string             `json:"hook_references"`
		IsSite          bool                 `json:"is_site"`
		SortBy          int                  `json:"sort_by"`
		UserGroupOwners []string             `json:"user_group_owners"`
		UserOwners      []string             `json:"user_owners"`
	} `json:"apis"`
	Pages int `json:"pages"`
}

type tykConnection struct {
	client  *http.Client
	baseURL *string
	secret  *string
}

func tykClient(u *string, s *string) *tykConnection {
	return &tykConnection{
		client: &http.Client{
			Timeout: connectionTimeout,
		},
		baseURL: u,
		secret:  s,
	}
}

func (tc *tykConnection) fetchGatewayAPIs() ([]apidef.APIDefinition, error) {
	req, err := http.NewRequest("GET", *tc.baseURL+"/tyk/apis", nil)
	if err != nil {
		log.Fatal("Error reading request: ", err)
	}
	req.Header.Set("x-tyk-authorization", *tc.secret)
	resp, err := tc.client.Do(req)
	if err != nil {
		log.Fatal("Error reading response: ", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("Error reading body: ", err)
	}
	//fmt.Printf("%s\n", body)
	var apis []apidef.APIDefinition
	err = json.Unmarshal(body, &apis)
	return apis, err
}

func (tc *tykConnection) fetchDashboardAPIs() (*OrgAPIs, error) {
	var apis OrgAPIs
	req, err := http.NewRequest("GET", *tc.baseURL+"/api/apis", nil)
	if err != nil {
		log.Fatal("Error reading request: ", err)
	}
	req.Header.Set("Authorization", *tc.secret)
	resp, err := tc.client.Do(req)
	if err != nil {
		log.Fatal("Error reading response: ", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("Error reading body: ", err)
	}
	// fmt.Printf("%s\n", body)
	err = json.Unmarshal(body, &apis)
	return &apis, err
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
	if *dashboard != "" {
		con := tykClient(dashboard, secret)
		results, err := con.fetchDashboardAPIs()
		if err != nil {
			log.Fatal("Cannot unmarshal dashboard APIs: ", err)
		}
		for _, api := range results.Apis {
			fmt.Printf("%s; %s; %s; %s; %s\n", api.APIDefinition.Name, api.APIDefinition.APIID, api.APIDefinition.Proxy.ListenPath, api.APIDefinition.Proxy.TargetURL, strings.Join(api.APIDefinition.Tags, ", "))
		}
	} else {
		con := tykClient(gateway, secret)
		results, err := con.fetchGatewayAPIs()
		if err != nil {
			log.Fatal("Cannot unmarshal gateway APIs: ", err)
		}
		for _, api := range results {
			fmt.Printf("%s; %s; %s; %s; %s\n", api.Name, api.APIID, api.Proxy.ListenPath, api.Proxy.TargetURL, strings.Join(api.Tags, ", "))
		}
		// fmt.Println(results)
	}
}
