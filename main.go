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

// OrgAPIs contains the APIs for the whole organisation
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

func (tc *tykConnection) fetchGatewayAPI(api_path string) ([]apidef.APIDefinition, []byte, error) {
	req, err := http.NewRequest("GET", *tc.baseURL+api_path, nil)
	fmt.Println(*tc.baseURL + api_path)
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
	return apis, body, err
}

func (tc *tykConnection) fetchDashboardAPI(api_path string) (*OrgAPIs, []byte, error) {
	var apis OrgAPIs
	req, err := http.NewRequest("GET", *tc.baseURL+api_path, nil)
	fmt.Println(*tc.baseURL + api_path)
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
	return &apis, body, err
}

func main() {
	dashboard := flag.String("dashboard", "", "Dashboard host URL")
	gateway := flag.String("gateway", "", "Gateway URL")
	secret := flag.String("secret", "", "Either dashboard credentials or the gateway secret")
	// list := flag.Bool("list", false, "List rather than sence check")
	// check := flag.Bool("check", false, "Sense check rather than list")
	apis := flag.Bool("apis", false, "Check/list the defined APIs")
	users := flag.Bool("users", false, "Check/list the users")
	probe := flag.String("probe", "", "Connect to the given dashboard or gateway API and dump the results")
	// json := flag.Bool("dumpJSON", false, "Dump the JSON")
	flag.Parse()
	if (*dashboard != "" && *gateway != "") || (*dashboard == "" && *gateway == "") {
		log.Fatal("Specify exactly one of --dashboard or --gateway")
	}
	// if (*list && *check) || (!*list && !*check) {
	// 	log.Fatal("Specify exactly one of list(-l) or check(-c)")
	// }
	if *secret == "" {
		log.Fatal("Must provide a secret(-secret)")
	}
	if !(*apis || *users || *probe != "") {
		log.Fatal("Specify exactly one of --apis, --users or --probe")
	}
	if *probe != "" {
		// we're connecting to a named API and dumping the results
		if *dashboard != "" {
			// setup dashboard connection
			con := tykClient(dashboard, secret)
			result, _, err := con.fetchDashboardAPI(*probe)
			if err != nil {
				log.Fatal("Cannot unmarshal dashboard APIs: ", err)
			}
			json, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(json))
		} else if *gateway != "" {
			// setup gateway connection
			con := tykClient(gateway, secret)
			result, _, err := con.fetchGatewayAPI(*probe)
			if err != nil {
				log.Fatal("Cannot unmarshal gateway API: ", err)
			}
			json, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(json))
		} else {
			// neither dashboard nor gateway so give up
			log.Fatal("When probing you must give either dashboard or gateway URL")
		}
	} else if *dashboard != "" {
		con := tykClient(dashboard, secret)
		results, _, err := con.fetchDashboardAPI("/api/apis?p=0")
		if err != nil {
			log.Fatal("Cannot unmarshal dashboard APIs: ", err)
		}
		for _, api := range results.Apis {
			fmt.Printf("%s; %s; %s; %s; %s\n", api.APIDefinition.Name, api.APIDefinition.APIID, api.APIDefinition.Proxy.ListenPath, api.APIDefinition.Proxy.TargetURL, strings.Join(api.APIDefinition.Tags, ", "))
		}
	} else {
		con := tykClient(gateway, secret)
		results, _, err := con.fetchGatewayAPI("/tyk/apis")
		if err != nil {
			log.Fatal("Cannot unmarshal gateway APIs: ", err)
		}
		for _, api := range results {
			fmt.Printf("%s; %s; %s; %s; %s\n", api.Name, api.APIID, api.Proxy.ListenPath, api.Proxy.TargetURL, strings.Join(api.Tags, ", "))
		}
	}
	// fmt.Println(results)
}
