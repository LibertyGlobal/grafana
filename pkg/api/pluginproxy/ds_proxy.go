package pluginproxy

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/grafana/grafana/pkg/components/simplejson"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/opentracing/opentracing-go"
	"golang.org/x/oauth2"

	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/log"
	"github.com/grafana/grafana/pkg/login/social"
	m "github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util"
)

var (
	logger = log.New("data-proxy-log")
	client = newHTTPClient()
)

type DataSourceProxy struct {
	ds        *m.DataSource
	ctx       *m.ReqContext
	targetUrl *url.URL
	proxyPath string
	route     *plugins.AppPluginRoute
	plugin    *plugins.DataSourcePlugin
	cfg       *setting.Cfg
}

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

func NewDataSourceProxy(ds *m.DataSource, plugin *plugins.DataSourcePlugin, ctx *m.ReqContext, proxyPath string, cfg *setting.Cfg) *DataSourceProxy {
	targetURL, _ := url.Parse(ds.Url)

	return &DataSourceProxy{
		ds:        ds,
		plugin:    plugin,
		ctx:       ctx,
		proxyPath: proxyPath,
		targetUrl: targetURL,
		cfg:       cfg,
	}
}

func newHTTPClient() httpClient {
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyFromEnvironment},
	}
}

func (proxy *DataSourceProxy) HandleRequest() {
	if err := proxy.validateRequest(); err != nil {
		proxy.ctx.JsonApiErr(403, err.Error(), nil)
		return
	}

	reverseProxy := &httputil.ReverseProxy{
		Director:      proxy.getDirector(),
		FlushInterval: time.Millisecond * 200,
	}

	var err error
	reverseProxy.Transport, err = proxy.ds.GetHttpTransport()
	if err != nil {
		proxy.ctx.JsonApiErr(400, "Unable to load TLS certificate", err)
		return
	}

	proxy.logRequest()

	span, ctx := opentracing.StartSpanFromContext(proxy.ctx.Req.Context(), "datasource reverse proxy")
	proxy.ctx.Req.Request = proxy.ctx.Req.WithContext(ctx)

	defer span.Finish()
	span.SetTag("datasource_id", proxy.ds.Id)
	span.SetTag("datasource_type", proxy.ds.Type)
	span.SetTag("user_id", proxy.ctx.SignedInUser.UserId)
	span.SetTag("org_id", proxy.ctx.SignedInUser.OrgId)

	proxy.addTraceFromHeaderValue(span, "X-Panel-Id", "panel_id")
	proxy.addTraceFromHeaderValue(span, "X-Dashboard-Id", "dashboard_id")

	opentracing.GlobalTracer().Inject(
		span.Context(),
		opentracing.HTTPHeaders,
		opentracing.HTTPHeadersCarrier(proxy.ctx.Req.Request.Header))

	originalSetCookie := proxy.ctx.Resp.Header().Get("Set-Cookie")

	reverseProxy.ServeHTTP(proxy.ctx.Resp, proxy.ctx.Req.Request)
	proxy.ctx.Resp.Header().Del("Set-Cookie")

	if originalSetCookie != "" {
		proxy.ctx.Resp.Header().Set("Set-Cookie", originalSetCookie)
	}
}

func (proxy *DataSourceProxy) addTraceFromHeaderValue(span opentracing.Span, headerName string, tagName string) {
	panelId := proxy.ctx.Req.Header.Get(headerName)
	dashId, err := strconv.Atoi(panelId)
	if err == nil {
		span.SetTag(tagName, dashId)
	}
}

func (proxy *DataSourceProxy) useCustomHeaders(req *http.Request) {
	decryptSdj := proxy.ds.SecureJsonData.Decrypt()
	index := 1
	for {
		headerNameSuffix := fmt.Sprintf("httpHeaderName%d", index)
		headerValueSuffix := fmt.Sprintf("httpHeaderValue%d", index)
		if key := proxy.ds.JsonData.Get(headerNameSuffix).MustString(); key != "" {
			if val, ok := decryptSdj[headerValueSuffix]; ok {
				// remove if exists
				if req.Header.Get(key) != "" {
					req.Header.Del(key)
				}
				req.Header.Add(key, val)
				logger.Debug("Using custom header ", "CustomHeaders", key)
			}
		} else {
			break
		}
		index += 1
	}
}

func (proxy *DataSourceProxy) getDirector() func(req *http.Request) {
	return func(req *http.Request) {
		req.URL.Scheme = proxy.targetUrl.Scheme
		req.URL.Host = proxy.targetUrl.Host
		req.Host = proxy.targetUrl.Host

		reqQueryVals := req.URL.Query()

		if proxy.ds.Type == m.DS_INFLUXDB_08 {
			req.URL.Path = util.JoinURLFragments(proxy.targetUrl.Path, "db/"+proxy.ds.Database+"/"+proxy.proxyPath)
			reqQueryVals.Add("u", proxy.ds.User)
			reqQueryVals.Add("p", proxy.ds.DecryptedPassword())
			req.URL.RawQuery = reqQueryVals.Encode()
		} else if proxy.ds.Type == m.DS_INFLUXDB {
			req.URL.Path = util.JoinURLFragments(proxy.targetUrl.Path, proxy.proxyPath)
			req.URL.RawQuery = reqQueryVals.Encode()
			if !proxy.ds.BasicAuth {
				req.Header.Del("Authorization")
				req.Header.Add("Authorization", util.GetBasicAuthHeader(proxy.ds.User, proxy.ds.DecryptedPassword()))
			}
		} else {
			req.URL.Path = util.JoinURLFragments(proxy.targetUrl.Path, proxy.proxyPath)
		}
		if proxy.ds.BasicAuth {
			req.Header.Del("Authorization")
			req.Header.Add("Authorization", util.GetBasicAuthHeader(proxy.ds.BasicAuthUser, proxy.ds.DecryptedBasicAuthPassword()))
		}

		// Lookup and use custom headers
		if proxy.ds.SecureJsonData != nil {
			proxy.useCustomHeaders(req)
		}

		dsAuth := req.Header.Get("X-DS-Authorization")
		if len(dsAuth) > 0 {
			req.Header.Del("X-DS-Authorization")
			req.Header.Del("Authorization")
			req.Header.Add("Authorization", dsAuth)
		}

		if proxy.cfg.SendUserHeader && !proxy.ctx.SignedInUser.IsAnonymous {
			req.Header.Add("X-Grafana-User", proxy.ctx.SignedInUser.Login)
		}

		// clear cookie header, except for whitelisted cookies
		var keptCookies []*http.Cookie
		if proxy.ds.JsonData != nil {
			if keepCookies := proxy.ds.JsonData.Get("keepCookies"); keepCookies != nil {
				keepCookieNames := keepCookies.MustStringArray()
				for _, c := range req.Cookies() {
					for _, v := range keepCookieNames {
						if c.Name == v {
							keptCookies = append(keptCookies, c)
						}
					}
				}
			}
		}
		req.Header.Del("Cookie")
		for _, c := range keptCookies {
			req.AddCookie(c)
		}

		// clear X-Forwarded Host/Port/Proto headers
		req.Header.Del("X-Forwarded-Host")
		req.Header.Del("X-Forwarded-Port")
		req.Header.Del("X-Forwarded-Proto")
		req.Header.Set("User-Agent", fmt.Sprintf("Grafana/%s", setting.BuildVersion))

		// Clear Origin and Referer to avoir CORS issues
		req.Header.Del("Origin")
		req.Header.Del("Referer")

		// set X-Forwarded-For header
		if req.RemoteAddr != "" {
			remoteAddr, _, err := net.SplitHostPort(req.RemoteAddr)
			if err != nil {
				remoteAddr = req.RemoteAddr
			}
			if req.Header.Get("X-Forwarded-For") != "" {
				req.Header.Set("X-Forwarded-For", req.Header.Get("X-Forwarded-For")+", "+remoteAddr)
			} else {
				req.Header.Set("X-Forwarded-For", remoteAddr)
			}
		}

		if proxy.route != nil {
			ApplyRoute(proxy.ctx.Req.Context(), req, proxy.proxyPath, proxy.route, proxy.ds)
		}

		if proxy.ds.JsonData != nil && proxy.ds.JsonData.Get("oauthPassThru").MustBool() {
			addOAuthPassThruAuth(proxy.ctx, req)
		}
	}
}

func (proxy *DataSourceProxy) validateRequest() error {
	if !checkWhiteList(proxy.ctx, proxy.targetUrl.Host) {
		return errors.New("Target url is not a valid target")
	}

	if proxy.ds.Type == m.DS_PROMETHEUS {
		if proxy.ctx.Req.Request.Method == "DELETE" {
			return errors.New("Deletes not allowed on proxied Prometheus datasource")
		}
		if proxy.ctx.Req.Request.Method == "PUT" {
			return errors.New("Puts not allowed on proxied Prometheus datasource")
		}
		if proxy.ctx.Req.Request.Method == "POST" && !(proxy.proxyPath == "api/v1/query" || proxy.proxyPath == "api/v1/query_range") {
			return errors.New("Posts not allowed on proxied Prometheus datasource except on /query and /query_range")
		}
	}

	if proxy.ds.Type == m.DS_ES {
		logger.Debug("ES datasource: entering validation")

		if proxy.ctx.Req.Request.Method == "DELETE" {
			return errors.New("Deletes not allowed on proxied Elasticsearch datasource")
		}
		if proxy.ctx.Req.Request.Method == "PUT" {
			return errors.New("Puts not allowed on proxied Elasticsearch datasource")
		}
		if proxy.ctx.Req.Request.Method == "POST" && proxy.proxyPath != "_msearch" {
			return errors.New("Posts not allowed on proxied Elasticsearch datasource except on /_msearch")
		}

		var err error
		err = proxy.validateESSearchIndexTemplate()
		if err != nil {
			logger.Debug("ES datasource: search validation have failed", "error", err)
			return err
		}

		err = proxy.validateESMappingIndexTemplate()
		if err != nil {
			logger.Debug("ES datasource: mapping validation have failed", "error", err)
			return err
		}

		logger.Debug("ES datasource: validation is success")
	}

	// found route if there are any
	if len(proxy.plugin.Routes) > 0 {
		for _, route := range proxy.plugin.Routes {
			// method match
			if route.Method != "" && route.Method != "*" && route.Method != proxy.ctx.Req.Method {
				continue
			}

			if route.ReqRole.IsValid() {
				if !proxy.ctx.HasUserRole(route.ReqRole) {
					return errors.New("Plugin proxy route access denied")
				}
			}

			if strings.HasPrefix(proxy.proxyPath, route.Path) {
				proxy.route = route
				break
			}
		}
	}

	return nil
}

// Validates that the ElasticSearch mapping request have been sent to
// an index which is matching the index template of the data source.
// Returns either and error or nil if all indices are matching.
func (proxy *DataSourceProxy) validateESMappingIndexTemplate() error {
	// this check applies only to the _mapping API
	if !(strings.Contains(proxy.proxyPath, "_mapping")) {
		return nil
	}

	logger.Debug(fmt.Sprintf("Check if request path: '%s' matches the datasource pattern", proxy.proxyPath))
	proxyPathParts := strings.Split(proxy.proxyPath, "/")
	logger.Debug(fmt.Sprintf("Got proxy path parts: '%s'", strings.Join(proxyPathParts, ",")))

	if len(proxyPathParts) > 1 {
		indexNames := proxyPathParts[0:1]
		logger.Debug(fmt.Sprintf("The index name part is: '%s'", strings.Join(indexNames, ",")))
		err := proxy.checkIndicesMatchTemplate(indexNames)
		if err != nil {
			logger.Debug("The mapping match have failed", "error", err)
			return err
		}
	} else {
		logger.Debug("The request does not contain the index part, check is success")
	}

	return nil
}

// Validates that all of the ElasticSearch msearch requests contains indices
// which are match the index template specified in the datasource settings
// It extracts the base part of the index template and checks if every
// requested index matches this template.
// Returns either and error or nil if all indices are matching.
func (proxy *DataSourceProxy) validateESSearchIndexTemplate() error {
	// this check applies only to the _msearch API
	if !(strings.Contains(proxy.proxyPath, "_msearch")) {
		return nil
	}

	requestBodyBytes, err := ioutil.ReadAll(proxy.ctx.Req.Request.Body)
	if err != nil {
		logger.Error("Could not read the request body during validation", "error", err)
		return err
	}
	proxy.ctx.Req.Request.Body = ioutil.NopCloser(bytes.NewBuffer(requestBodyBytes))

	requestBodyString := string(requestBodyBytes)
	logger.Debug(fmt.Sprintf("Processing full request body: '%s'", strings.Replace(requestBodyString, "\n", "\\n", -1)))

	requestBodyParts := strings.Split(strings.Replace(requestBodyString, "\r\n", "\n", -1), "\n")
	logger.Debug(fmt.Sprintf("Got '%d' request body parts after splitting: '%s'", len(requestBodyParts), strings.Join(requestBodyParts, "|")))

	for _, requestBody := range requestBodyParts {
		err = proxy.checkRequestMatchTemplate(requestBody)
		if err != nil {
			logger.Debug("Search request validation have failed", "error", err)
			return err
		}
	}

	return err
}

// Check if a single JSON request matches the index pattern
func (proxy *DataSourceProxy) checkRequestMatchTemplate(requestBody string) error {
	logger.Debug(fmt.Sprintf("Processing request body part: '%s'", requestBody))
	if len(requestBody) == 0 {
		logger.Debug("Request body part is empty, check is success")
		return nil
	}

	requestJson, err := simplejson.NewJson([]byte(requestBody))
	if err != nil {
		logger.Debug("Request body part is broken, check is failure", "error", err)
		return err
	}

	requestIndices := make([]string, 0)

	_, err = requestJson.Get("index").StringArray()
	if err == nil {
		jsonIndices, err := requestJson.Get("index").StringArray()
		if err == nil && len(jsonIndices) > 0 {
			logger.Debug(fmt.Sprintf("Adding indices to the list: '%s'", strings.Join(jsonIndices, ",")))
			requestIndices = append(requestIndices, jsonIndices...)
		}
	} else {
		jsonIndex, err := requestJson.Get("index").String()
		if err == nil && len(jsonIndex) > 0 {
			logger.Debug(fmt.Sprintf("Adding index to the list: '%s'", jsonIndex))
			requestIndices = append(requestIndices, jsonIndex)
		}
	}

	logger.Debug(fmt.Sprintf("From this request body part we got '%d' indices: '%s'", len(requestIndices), strings.Join(requestIndices, ",")))

	if len(requestIndices) == 0 {
		// this is a data part of the msearch request which does not contain the indices list
		logger.Debug("There are no index names in this request body part, it must be data part, check is success!")
		return nil
	}

	return proxy.checkIndicesMatchTemplate(requestIndices)
}

// Check if an array of index names matches the index pattern
func (proxy *DataSourceProxy) checkIndicesMatchTemplate(requestIndices []string) error {
	var templateError error
	basePart, _, ltr := proxy.getIndexTemplateParts()

	logger.Debug(fmt.Sprintf("Check if the template base part: '%s' is matching the index list: '%s'", basePart, strings.Join(requestIndices, ",")))

	for _, requestIndex := range requestIndices {
		logger.Debug(fmt.Sprintf("Check if the template base part: '%s' is matching the index: '%s' with left-to-rigth: %t", basePart, requestIndex, ltr))

		if ltr {
			if !strings.HasPrefix(requestIndex, basePart) {
				templateError = errors.New(fmt.Sprintf("The request index name: '%s' does not start with: '%s'!", requestIndex, basePart))
				logger.Debug("No, template doesn't match", "error", templateError)
				return templateError
			}
		} else {
			if !strings.HasSuffix(requestIndex, basePart) {
				templateError = errors.New(fmt.Sprintf("The request index name: '%s' does not end with: '%s'!", requestIndex, basePart))
				logger.Debug("No, template doesn't match", "error", templateError)
				return templateError
			}
		}

		logger.Debug("Yes, template does match")
	}

	return nil
}

// Split the index name to the base and date parts
func (proxy *DataSourceProxy) getIndexTemplateParts() (string, string, bool) {
	indexInterval := proxy.ds.JsonData.Get("interval").MustString()
	if indexInterval == "" {
		return proxy.ds.Database, "", false
	}

	datePart := ""
	basePart := ""
	ltr := false

	if strings.HasPrefix(proxy.ds.Database, "[") {
		parts := strings.Split(strings.TrimLeft(proxy.ds.Database, "["), "]")
		basePart = parts[0]
		if len(parts) == 2 {
			datePart = parts[1]
		} else {
			datePart = basePart
			basePart = ""
		}
		ltr = true
	} else if strings.HasSuffix(proxy.ds.Database, "]") {
		parts := strings.Split(strings.TrimRight(proxy.ds.Database, "]"), "[")
		datePart = parts[0]
		if len(parts) == 2 {
			basePart = parts[1]
		} else {
			basePart = ""
		}
		ltr = false
	}

	return basePart, datePart, ltr
}

func (proxy *DataSourceProxy) logRequest() {
	if !setting.DataProxyLogging {
		return
	}

	var body string
	if proxy.ctx.Req.Request.Body != nil {
		buffer, err := ioutil.ReadAll(proxy.ctx.Req.Request.Body)
		if err == nil {
			proxy.ctx.Req.Request.Body = ioutil.NopCloser(bytes.NewBuffer(buffer))
			body = string(buffer)
		}
	}

	logger.Info("Proxying incoming request",
		"userid", proxy.ctx.UserId,
		"orgid", proxy.ctx.OrgId,
		"username", proxy.ctx.Login,
		"datasource", proxy.ds.Type,
		"uri", proxy.ctx.Req.RequestURI,
		"method", proxy.ctx.Req.Request.Method,
		"body", body)
}

func checkWhiteList(c *m.ReqContext, host string) bool {
	if host != "" && len(setting.DataProxyWhiteList) > 0 {
		if _, exists := setting.DataProxyWhiteList[host]; !exists {
			c.JsonApiErr(403, "Data proxy hostname and ip are not included in whitelist", nil)
			return false
		}
	}

	return true
}

func addOAuthPassThruAuth(c *m.ReqContext, req *http.Request) {
	authInfoQuery := &m.GetAuthInfoQuery{UserId: c.UserId}
	if err := bus.Dispatch(authInfoQuery); err != nil {
		logger.Error("Error feching oauth information for user", "error", err)
		return
	}

	provider := authInfoQuery.Result.AuthModule
	connect, ok := social.SocialMap[strings.TrimPrefix(provider, "oauth_")] // The socialMap keys don't have "oauth_" prefix, but everywhere else in the system does
	if !ok {
		logger.Error("Failed to find oauth provider with given name", "provider", provider)
		return
	}

	// TokenSource handles refreshing the token if it has expired
	token, err := connect.TokenSource(c.Req.Context(), &oauth2.Token{
		AccessToken:  authInfoQuery.Result.OAuthAccessToken,
		Expiry:       authInfoQuery.Result.OAuthExpiry,
		RefreshToken: authInfoQuery.Result.OAuthRefreshToken,
		TokenType:    authInfoQuery.Result.OAuthTokenType,
	}).Token()
	if err != nil {
		logger.Error("Failed to retrieve access token from oauth provider", "provider", authInfoQuery.Result.AuthModule)
		return
	}

	// If the tokens are not the same, update the entry in the DB
	if token.AccessToken != authInfoQuery.Result.OAuthAccessToken {
		updateAuthCommand := &m.UpdateAuthInfoCommand{
			UserId:     authInfoQuery.Result.Id,
			AuthModule: authInfoQuery.Result.AuthModule,
			AuthId:     authInfoQuery.Result.AuthId,
			OAuthToken: token,
		}
		if err := bus.Dispatch(updateAuthCommand); err != nil {
			logger.Error("Failed to update access token during token refresh", "error", err)
			return
		}
	}
	req.Header.Del("Authorization")
	req.Header.Add("Authorization", fmt.Sprintf("%s %s", token.Type(), token.AccessToken))
}
