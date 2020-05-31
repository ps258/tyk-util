package models

import "time"

// type ComicResponse struct {
// 	Month      string `json:"month"`
// 	Num        int    `json:"num"`
// 	Link       string `json:"link"`
// 	Year       string `json:"year"`
// 	News       string `json:"news"`
// 	SafeTitle  string `json:"safe_title"`
// 	Transcript string `json:"transcript"`
// 	Alt        string `json:"alt"`
// 	Img        string `json:"img"`
// 	Title      string `json:"title"`
// 	Day        string `json:"day"`
// }

// type Comic struct {
// 	Title       string `json:"title"`
// 	Number      int    `json:"number"`
// 	Date        string `json:"date"`
// 	Description string `json:"description"`
// 	Image       string `json:"image"`
// }

// Me a struct of my data
type Me struct {
	me   string
	time time.Time
}

// OrgAPIs contains the APIs for the while organisation
type OrgAPIs struct {
	Apis []struct {
		CreatedAt time.Time `json:"created_at"`
		APIModel  struct {
		} `json:"api_model"`
		APIDefinition struct {
			ID                  string `json:"id"`
			Name                string `json:"name"`
			Slug                string `json:"slug"`
			ListenPort          int    `json:"listen_port"`
			Protocol            string `json:"protocol"`
			EnableProxyProtocol bool   `json:"enable_proxy_protocol"`
			APIID               string `json:"api_id"`
			OrgID               string `json:"org_id"`
			UseKeyless          bool   `json:"use_keyless"`
			UseOauth2           bool   `json:"use_oauth2"`
			UseOpenid           bool   `json:"use_openid"`
			OpenidOptions       struct {
				Providers         []interface{} `json:"providers"`
				SegregateByClient bool          `json:"segregate_by_client"`
			} `json:"openid_options"`
			OauthMeta struct {
				AllowedAccessTypes    []interface{} `json:"allowed_access_types"`
				AllowedAuthorizeTypes []interface{} `json:"allowed_authorize_types"`
				AuthLoginRedirect     string        `json:"auth_login_redirect"`
			} `json:"oauth_meta"`
			Auth struct {
				UseParam          bool   `json:"use_param"`
				ParamName         string `json:"param_name"`
				UseCookie         bool   `json:"use_cookie"`
				CookieName        string `json:"cookie_name"`
				AuthHeaderName    string `json:"auth_header_name"`
				UseCertificate    bool   `json:"use_certificate"`
				ValidateSignature bool   `json:"validate_signature"`
				Signature         struct {
					Algorithm        string `json:"algorithm"`
					Header           string `json:"header"`
					Secret           string `json:"secret"`
					AllowedClockSkew int    `json:"allowed_clock_skew"`
					ErrorCode        int    `json:"error_code"`
					ErrorMessage     string `json:"error_message"`
				} `json:"signature"`
			} `json:"auth"`
			AuthConfigs struct {
				AuthToken struct {
					UseParam          bool   `json:"use_param"`
					ParamName         string `json:"param_name"`
					UseCookie         bool   `json:"use_cookie"`
					CookieName        string `json:"cookie_name"`
					AuthHeaderName    string `json:"auth_header_name"`
					UseCertificate    bool   `json:"use_certificate"`
					ValidateSignature bool   `json:"validate_signature"`
					Signature         struct {
						Algorithm        string `json:"algorithm"`
						Header           string `json:"header"`
						Secret           string `json:"secret"`
						AllowedClockSkew int    `json:"allowed_clock_skew"`
						ErrorCode        int    `json:"error_code"`
						ErrorMessage     string `json:"error_message"`
					} `json:"signature"`
				} `json:"authToken"`
				Basic struct {
					UseParam          bool   `json:"use_param"`
					ParamName         string `json:"param_name"`
					UseCookie         bool   `json:"use_cookie"`
					CookieName        string `json:"cookie_name"`
					AuthHeaderName    string `json:"auth_header_name"`
					UseCertificate    bool   `json:"use_certificate"`
					ValidateSignature bool   `json:"validate_signature"`
					Signature         struct {
						Algorithm        string `json:"algorithm"`
						Header           string `json:"header"`
						Secret           string `json:"secret"`
						AllowedClockSkew int    `json:"allowed_clock_skew"`
						ErrorCode        int    `json:"error_code"`
						ErrorMessage     string `json:"error_message"`
					} `json:"signature"`
				} `json:"basic"`
				Coprocess struct {
					UseParam          bool   `json:"use_param"`
					ParamName         string `json:"param_name"`
					UseCookie         bool   `json:"use_cookie"`
					CookieName        string `json:"cookie_name"`
					AuthHeaderName    string `json:"auth_header_name"`
					UseCertificate    bool   `json:"use_certificate"`
					ValidateSignature bool   `json:"validate_signature"`
					Signature         struct {
						Algorithm        string `json:"algorithm"`
						Header           string `json:"header"`
						Secret           string `json:"secret"`
						AllowedClockSkew int    `json:"allowed_clock_skew"`
						ErrorCode        int    `json:"error_code"`
						ErrorMessage     string `json:"error_message"`
					} `json:"signature"`
				} `json:"coprocess"`
				Hmac struct {
					UseParam          bool   `json:"use_param"`
					ParamName         string `json:"param_name"`
					UseCookie         bool   `json:"use_cookie"`
					CookieName        string `json:"cookie_name"`
					AuthHeaderName    string `json:"auth_header_name"`
					UseCertificate    bool   `json:"use_certificate"`
					ValidateSignature bool   `json:"validate_signature"`
					Signature         struct {
						Algorithm        string `json:"algorithm"`
						Header           string `json:"header"`
						Secret           string `json:"secret"`
						AllowedClockSkew int    `json:"allowed_clock_skew"`
						ErrorCode        int    `json:"error_code"`
						ErrorMessage     string `json:"error_message"`
					} `json:"signature"`
				} `json:"hmac"`
				Jwt struct {
					UseParam          bool   `json:"use_param"`
					ParamName         string `json:"param_name"`
					UseCookie         bool   `json:"use_cookie"`
					CookieName        string `json:"cookie_name"`
					AuthHeaderName    string `json:"auth_header_name"`
					UseCertificate    bool   `json:"use_certificate"`
					ValidateSignature bool   `json:"validate_signature"`
					Signature         struct {
						Algorithm        string `json:"algorithm"`
						Header           string `json:"header"`
						Secret           string `json:"secret"`
						AllowedClockSkew int    `json:"allowed_clock_skew"`
						ErrorCode        int    `json:"error_code"`
						ErrorMessage     string `json:"error_message"`
					} `json:"signature"`
				} `json:"jwt"`
				Oauth struct {
					UseParam          bool   `json:"use_param"`
					ParamName         string `json:"param_name"`
					UseCookie         bool   `json:"use_cookie"`
					CookieName        string `json:"cookie_name"`
					AuthHeaderName    string `json:"auth_header_name"`
					UseCertificate    bool   `json:"use_certificate"`
					ValidateSignature bool   `json:"validate_signature"`
					Signature         struct {
						Algorithm        string `json:"algorithm"`
						Header           string `json:"header"`
						Secret           string `json:"secret"`
						AllowedClockSkew int    `json:"allowed_clock_skew"`
						ErrorCode        int    `json:"error_code"`
						ErrorMessage     string `json:"error_message"`
					} `json:"signature"`
				} `json:"oauth"`
				Oidc struct {
					UseParam          bool   `json:"use_param"`
					ParamName         string `json:"param_name"`
					UseCookie         bool   `json:"use_cookie"`
					CookieName        string `json:"cookie_name"`
					AuthHeaderName    string `json:"auth_header_name"`
					UseCertificate    bool   `json:"use_certificate"`
					ValidateSignature bool   `json:"validate_signature"`
					Signature         struct {
						Algorithm        string `json:"algorithm"`
						Header           string `json:"header"`
						Secret           string `json:"secret"`
						AllowedClockSkew int    `json:"allowed_clock_skew"`
						ErrorCode        int    `json:"error_code"`
						ErrorMessage     string `json:"error_message"`
					} `json:"signature"`
				} `json:"oidc"`
			} `json:"auth_configs"`
			UseBasicAuth bool `json:"use_basic_auth"`
			BasicAuth    struct {
				DisableCaching     bool   `json:"disable_caching"`
				CacheTTL           int    `json:"cache_ttl"`
				ExtractFromBody    bool   `json:"extract_from_body"`
				BodyUserRegexp     string `json:"body_user_regexp"`
				BodyPasswordRegexp string `json:"body_password_regexp"`
			} `json:"basic_auth"`
			UseMutualTLSAuth     bool          `json:"use_mutual_tls_auth"`
			ClientCertificates   []interface{} `json:"client_certificates"`
			UpstreamCertificates struct {
			} `json:"upstream_certificates"`
			PinnedPublicKeys struct {
			} `json:"pinned_public_keys"`
			EnableJwt                  bool          `json:"enable_jwt"`
			UseStandardAuth            bool          `json:"use_standard_auth"`
			UseGoPluginAuth            bool          `json:"use_go_plugin_auth"`
			EnableCoprocessAuth        bool          `json:"enable_coprocess_auth"`
			JwtSigningMethod           string        `json:"jwt_signing_method"`
			JwtSource                  string        `json:"jwt_source"`
			JwtIdentityBaseField       string        `json:"jwt_identity_base_field"`
			JwtClientBaseField         string        `json:"jwt_client_base_field"`
			JwtPolicyFieldName         string        `json:"jwt_policy_field_name"`
			JwtDefaultPolicies         []interface{} `json:"jwt_default_policies"`
			JwtIssuedAtValidationSkew  int           `json:"jwt_issued_at_validation_skew"`
			JwtExpiresAtValidationSkew int           `json:"jwt_expires_at_validation_skew"`
			JwtNotBeforeValidationSkew int           `json:"jwt_not_before_validation_skew"`
			JwtSkipKid                 bool          `json:"jwt_skip_kid"`
			JwtScopeToPolicyMapping    struct {
			} `json:"jwt_scope_to_policy_mapping"`
			JwtScopeClaimName string `json:"jwt_scope_claim_name"`
			Notifications     struct {
				SharedSecret        string `json:"shared_secret"`
				OauthOnKeychangeURL string `json:"oauth_on_keychange_url"`
			} `json:"notifications"`
			EnableSignatureChecking bool          `json:"enable_signature_checking"`
			HmacAllowedClockSkew    int           `json:"hmac_allowed_clock_skew"`
			HmacAllowedAlgorithms   []interface{} `json:"hmac_allowed_algorithms"`
			RequestSigning          struct {
				IsEnabled       bool          `json:"is_enabled"`
				Secret          string        `json:"secret"`
				KeyID           string        `json:"key_id"`
				Algorithm       string        `json:"algorithm"`
				HeaderList      []interface{} `json:"header_list"`
				CertificateID   string        `json:"certificate_id"`
				SignatureHeader string        `json:"signature_header"`
			} `json:"request_signing"`
			BaseIdentityProvidedBy string `json:"base_identity_provided_by"`
			Definition             struct {
				Location  string `json:"location"`
				Key       string `json:"key"`
				StripPath bool   `json:"strip_path"`
			} `json:"definition"`
			VersionData struct {
				NotVersioned   bool   `json:"not_versioned"`
				DefaultVersion string `json:"default_version"`
				Versions       struct {
					Default struct {
						Name    string `json:"name"`
						Expires string `json:"expires"`
						Paths   struct {
							Ignored   []interface{} `json:"ignored"`
							WhiteList []interface{} `json:"white_list"`
							BlackList []interface{} `json:"black_list"`
						} `json:"paths"`
						UseExtendedPaths bool `json:"use_extended_paths"`
						ExtendedPaths    struct {
						} `json:"extended_paths"`
						GlobalHeaders struct {
						} `json:"global_headers"`
						GlobalHeadersRemove []interface{} `json:"global_headers_remove"`
						IgnoreEndpointCase  bool          `json:"ignore_endpoint_case"`
						GlobalSizeLimit     int           `json:"global_size_limit"`
						OverrideTarget      string        `json:"override_target"`
					} `json:"Default"`
				} `json:"versions"`
			} `json:"version_data"`
			UptimeTests struct {
				CheckList []interface{} `json:"check_list"`
				Config    struct {
					ExpireUtimeAfter int `json:"expire_utime_after"`
					ServiceDiscovery struct {
						UseDiscoveryService bool   `json:"use_discovery_service"`
						QueryEndpoint       string `json:"query_endpoint"`
						UseNestedQuery      bool   `json:"use_nested_query"`
						ParentDataPath      string `json:"parent_data_path"`
						DataPath            string `json:"data_path"`
						PortDataPath        string `json:"port_data_path"`
						TargetPath          string `json:"target_path"`
						UseTargetList       bool   `json:"use_target_list"`
						CacheTimeout        int    `json:"cache_timeout"`
						EndpointReturnsList bool   `json:"endpoint_returns_list"`
					} `json:"service_discovery"`
					RecheckWait int `json:"recheck_wait"`
				} `json:"config"`
			} `json:"uptime_tests"`
			Proxy struct {
				PreserveHostHeader          bool          `json:"preserve_host_header"`
				ListenPath                  string        `json:"listen_path"`
				TargetURL                   string        `json:"target_url"`
				DisableStripSlash           bool          `json:"disable_strip_slash"`
				StripListenPath             bool          `json:"strip_listen_path"`
				EnableLoadBalancing         bool          `json:"enable_load_balancing"`
				TargetList                  []interface{} `json:"target_list"`
				CheckHostAgainstUptimeTests bool          `json:"check_host_against_uptime_tests"`
				ServiceDiscovery            struct {
					UseDiscoveryService bool   `json:"use_discovery_service"`
					QueryEndpoint       string `json:"query_endpoint"`
					UseNestedQuery      bool   `json:"use_nested_query"`
					ParentDataPath      string `json:"parent_data_path"`
					DataPath            string `json:"data_path"`
					PortDataPath        string `json:"port_data_path"`
					TargetPath          string `json:"target_path"`
					UseTargetList       bool   `json:"use_target_list"`
					CacheTimeout        int    `json:"cache_timeout"`
					EndpointReturnsList bool   `json:"endpoint_returns_list"`
				} `json:"service_discovery"`
				Transport struct {
					SslInsecureSkipVerify   bool          `json:"ssl_insecure_skip_verify"`
					SslCiphers              []interface{} `json:"ssl_ciphers"`
					SslMinVersion           int           `json:"ssl_min_version"`
					SslForceCommonNameCheck bool          `json:"ssl_force_common_name_check"`
					ProxyURL                string        `json:"proxy_url"`
				} `json:"transport"`
			} `json:"proxy"`
			DisableRateLimit bool `json:"disable_rate_limit"`
			DisableQuota     bool `json:"disable_quota"`
			CustomMiddleware struct {
				Pre         []interface{} `json:"pre"`
				Post        []interface{} `json:"post"`
				PostKeyAuth []interface{} `json:"post_key_auth"`
				AuthCheck   struct {
					Name           string `json:"name"`
					Path           string `json:"path"`
					RequireSession bool   `json:"require_session"`
					RawBodyOnly    bool   `json:"raw_body_only"`
				} `json:"auth_check"`
				Response    []interface{} `json:"response"`
				Driver      string        `json:"driver"`
				IDExtractor struct {
					ExtractFrom     string `json:"extract_from"`
					ExtractWith     string `json:"extract_with"`
					ExtractorConfig struct {
					} `json:"extractor_config"`
				} `json:"id_extractor"`
			} `json:"custom_middleware"`
			CustomMiddlewareBundle string `json:"custom_middleware_bundle"`
			CacheOptions           struct {
				CacheTimeout               int           `json:"cache_timeout"`
				EnableCache                bool          `json:"enable_cache"`
				CacheAllSafeRequests       bool          `json:"cache_all_safe_requests"`
				CacheResponseCodes         []interface{} `json:"cache_response_codes"`
				EnableUpstreamCacheControl bool          `json:"enable_upstream_cache_control"`
				CacheControlTTLHeader      string        `json:"cache_control_ttl_header"`
				CacheByHeaders             []interface{} `json:"cache_by_headers"`
			} `json:"cache_options"`
			SessionLifetime int  `json:"session_lifetime"`
			Active          bool `json:"active"`
			Internal        bool `json:"internal"`
			AuthProvider    struct {
				Name          string `json:"name"`
				StorageEngine string `json:"storage_engine"`
				Meta          struct {
				} `json:"meta"`
			} `json:"auth_provider"`
			SessionProvider struct {
				Name          string `json:"name"`
				StorageEngine string `json:"storage_engine"`
				Meta          struct {
				} `json:"meta"`
			} `json:"session_provider"`
			EventHandlers struct {
				Events struct {
				} `json:"events"`
			} `json:"event_handlers"`
			EnableBatchRequestSupport bool          `json:"enable_batch_request_support"`
			EnableIPWhitelisting      bool          `json:"enable_ip_whitelisting"`
			AllowedIps                []interface{} `json:"allowed_ips"`
			EnableIPBlacklisting      bool          `json:"enable_ip_blacklisting"`
			BlacklistedIps            []interface{} `json:"blacklisted_ips"`
			DontSetQuotaOnCreate      bool          `json:"dont_set_quota_on_create"`
			ExpireAnalyticsAfter      int           `json:"expire_analytics_after"`
			ResponseProcessors        []interface{} `json:"response_processors"`
			CORS                      struct {
				Enable             bool          `json:"enable"`
				AllowedOrigins     []interface{} `json:"allowed_origins"`
				AllowedMethods     []interface{} `json:"allowed_methods"`
				AllowedHeaders     []interface{} `json:"allowed_headers"`
				ExposedHeaders     []interface{} `json:"exposed_headers"`
				AllowCredentials   bool          `json:"allow_credentials"`
				MaxAge             int           `json:"max_age"`
				OptionsPassthrough bool          `json:"options_passthrough"`
				Debug              bool          `json:"debug"`
			} `json:"CORS"`
			Domain            string        `json:"domain"`
			Certificates      []interface{} `json:"certificates"`
			DoNotTrack        bool          `json:"do_not_track"`
			Tags              []interface{} `json:"tags"`
			EnableContextVars bool          `json:"enable_context_vars"`
			ConfigData        struct {
			} `json:"config_data"`
			TagHeaders      []interface{} `json:"tag_headers"`
			GlobalRateLimit struct {
				Rate int `json:"rate"`
				Per  int `json:"per"`
			} `json:"global_rate_limit"`
			StripAuthData           bool `json:"strip_auth_data"`
			EnableDetailedRecording bool `json:"enable_detailed_recording"`
		} `json:"api_definition"`
		HookReferences  []interface{} `json:"hook_references"`
		IsSite          bool          `json:"is_site"`
		SortBy          int           `json:"sort_by"`
		UserGroupOwners []interface{} `json:"user_group_owners"`
		UserOwners      []interface{} `json:"user_owners"`
	} `json:"apis"`
	Pages int `json:"pages"`
}

// // Comic converts ComicResponse that we receive from the API to our application's output format, Comic
// func (cr ComicResponse) Comic() Comic {
// 	return Comic{
// 		Title:       cr.Title,
// 		Number:      cr.Num,
// 		Date:        cr.FormattedDate(),
// 		Description: cr.Alt,
// 		Image:       cr.Img,
// 	}
// }

// // PrettyString creates a pretty string of the Comic that we'll use as output
// func (c Comic) PrettyString() string {
// 	p := fmt.Sprintf(
// 		"Title: %s\nComic No: %d\nDate: %s\nDescription: %s\nImage: %s\n",
// 		c.Title, c.Number, c.Date, c.Description, c.Image)
// 	return p
// }

// // JSON converts the Comic struct to JSON, we'll use the JSON string as output
// func (c Comic) JSON() string {
// 	cJSON, err := json.Marshal(c)
// 	if err != nil {
// 		return ""
// 	}
// 	return string(cJSON)
// }
