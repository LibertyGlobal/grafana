package pluginproxy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/grafana/grafana/pkg/components/simplejson"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/grafana/grafana/pkg/api/datasource"
	"github.com/grafana/grafana/pkg/bus"
	glog "github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/services/oauthtoken"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util"
	"github.com/grafana/grafana/pkg/util/proxyutil"
	"github.com/opentracing/opentracing-go"
)

var (
	logger = glog.New("data-proxy-log")
	client = newHTTPClient()
)

type DataSourceProxy struct {
	ds        *models.DataSource
	ctx       *models.ReqContext
	targetUrl *url.URL
	proxyPath string
	route     *plugins.AppPluginRoute
	plugin    *plugins.DataSourcePlugin
	cfg       *setting.Cfg
}

type handleResponseTransport struct {
	transport http.RoundTripper
}

func (t *handleResponseTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := t.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	res.Header.Del("Set-Cookie")
	return res, nil
}

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type logWrapper struct {
	logger glog.Logger
}

// Write writes log messages as bytes from proxy
func (lw *logWrapper) Write(p []byte) (n int, err error) {
	withoutNewline := strings.TrimSuffix(string(p), "\n")
	lw.logger.Error("Data proxy error", "error", withoutNewline)
	return len(p), nil
}

// NewDataSourceProxy creates a new Datasource proxy
func NewDataSourceProxy(ds *models.DataSource, plugin *plugins.DataSourcePlugin, ctx *models.ReqContext,
	proxyPath string, cfg *setting.Cfg) (*DataSourceProxy, error) {
	targetURL, err := datasource.ValidateURL(ds.Type, ds.Url)
	if err != nil {
		return nil, err
	}

	return &DataSourceProxy{
		ds:        ds,
		plugin:    plugin,
		ctx:       ctx,
		proxyPath: proxyPath,
		targetUrl: targetURL,
		cfg:       cfg,
	}, nil
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

	proxyErrorLogger := logger.New("userId", proxy.ctx.UserId, "orgId", proxy.ctx.OrgId, "uname", proxy.ctx.Login,
		"path", proxy.ctx.Req.URL.Path, "remote_addr", proxy.ctx.RemoteAddr(), "referer", proxy.ctx.Req.Referer())

	transport, err := proxy.ds.GetHttpTransport()
	if err != nil {
		proxy.ctx.JsonApiErr(400, "Unable to load TLS certificate", err)
		return
	}

	reverseProxy := &httputil.ReverseProxy{
		Director:      proxy.director,
		FlushInterval: time.Millisecond * 200,
		ErrorLog:      log.New(&logWrapper{logger: proxyErrorLogger}, "", 0),
		Transport: &handleResponseTransport{
			transport: transport,
		},
		ModifyResponse: func(resp *http.Response) error {
			if resp.StatusCode == 401 {
				// The data source rejected the request as unauthorized, convert to 400 (bad request)
				body, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					return fmt.Errorf("failed to read data source response body: %w", err)
				}
				_ = resp.Body.Close()

				proxyErrorLogger.Info("Authentication to data source failed", "body", string(body), "statusCode",
					resp.StatusCode)
				msg := "Authentication to data source failed"
				*resp = http.Response{
					StatusCode:    400,
					Status:        "Bad Request",
					Body:          ioutil.NopCloser(strings.NewReader(msg)),
					ContentLength: int64(len(msg)),
				}
			}
			return nil
		},
	}

	proxy.logRequest()

	span, ctx := opentracing.StartSpanFromContext(proxy.ctx.Req.Context(), "datasource reverse proxy")
	defer span.Finish()

	proxy.ctx.Req.Request = proxy.ctx.Req.WithContext(ctx)

	span.SetTag("datasource_name", proxy.ds.Name)
	span.SetTag("datasource_type", proxy.ds.Type)
	span.SetTag("user", proxy.ctx.SignedInUser.Login)
	span.SetTag("org_id", proxy.ctx.SignedInUser.OrgId)

	proxy.addTraceFromHeaderValue(span, "X-Panel-Id", "panel_id")
	proxy.addTraceFromHeaderValue(span, "X-Dashboard-Id", "dashboard_id")

	if err := opentracing.GlobalTracer().Inject(
		span.Context(),
		opentracing.HTTPHeaders,
		opentracing.HTTPHeadersCarrier(proxy.ctx.Req.Request.Header)); err != nil {
		logger.Error("Failed to inject span context instance", "err", err)
	}

	reverseProxy.ServeHTTP(proxy.ctx.Resp, proxy.ctx.Req.Request)
}

func (proxy *DataSourceProxy) addTraceFromHeaderValue(span opentracing.Span, headerName string, tagName string) {
	panelId := proxy.ctx.Req.Header.Get(headerName)
	dashId, err := strconv.Atoi(panelId)
	if err == nil {
		span.SetTag(tagName, dashId)
	}
}

func (proxy *DataSourceProxy) director(req *http.Request) {
	req.URL.Scheme = proxy.targetUrl.Scheme
	req.URL.Host = proxy.targetUrl.Host
	req.Host = proxy.targetUrl.Host

	reqQueryVals := req.URL.Query()

	switch proxy.ds.Type {
	case models.DS_INFLUXDB_08:
		req.URL.RawPath = util.JoinURLFragments(proxy.targetUrl.Path, "db/"+proxy.ds.Database+"/"+proxy.proxyPath)
		reqQueryVals.Add("u", proxy.ds.User)
		reqQueryVals.Add("p", proxy.ds.DecryptedPassword())
		req.URL.RawQuery = reqQueryVals.Encode()
	case models.DS_INFLUXDB:
		req.URL.RawPath = util.JoinURLFragments(proxy.targetUrl.Path, proxy.proxyPath)
		req.URL.RawQuery = reqQueryVals.Encode()
		if !proxy.ds.BasicAuth {
			req.Header.Set("Authorization", util.GetBasicAuthHeader(proxy.ds.User, proxy.ds.DecryptedPassword()))
		}
	default:
		req.URL.RawPath = util.JoinURLFragments(proxy.targetUrl.Path, proxy.proxyPath)
	}

	unescapedPath, err := url.PathUnescape(req.URL.RawPath)
	if err != nil {
		logger.Error("Failed to unescape raw path", "rawPath", req.URL.RawPath, "error", err)
		return
	}

	req.URL.Path = unescapedPath

	if proxy.ds.BasicAuth {
		req.Header.Set("Authorization", util.GetBasicAuthHeader(proxy.ds.BasicAuthUser,
			proxy.ds.DecryptedBasicAuthPassword()))
	}

	dsAuth := req.Header.Get("X-DS-Authorization")
	if len(dsAuth) > 0 {
		req.Header.Del("X-DS-Authorization")
		req.Header.Set("Authorization", dsAuth)
	}

	applyUserHeader(proxy.cfg.SendUserHeader, req, proxy.ctx.SignedInUser)

	keepCookieNames := []string{}
	if proxy.ds.JsonData != nil {
		if keepCookies := proxy.ds.JsonData.Get("keepCookies"); keepCookies != nil {
			keepCookieNames = keepCookies.MustStringArray()
		}
	}

	proxyutil.ClearCookieHeader(req, keepCookieNames)
	proxyutil.PrepareProxyRequest(req)

	req.Header.Set("User-Agent", fmt.Sprintf("Grafana/%s", setting.BuildVersion))

	// Clear Origin and Referer to avoir CORS issues
	req.Header.Del("Origin")
	req.Header.Del("Referer")

	if proxy.route != nil {
		ApplyRoute(proxy.ctx.Req.Context(), req, proxy.proxyPath, proxy.route, proxy.ds)
	}

	if oauthtoken.IsOAuthPassThruEnabled(proxy.ds) {
		if token := oauthtoken.GetCurrentOAuthToken(proxy.ctx.Req.Context(), proxy.ctx.SignedInUser); token != nil {
			req.Header.Set("Authorization", fmt.Sprintf("%s %s", token.Type(), token.AccessToken))
		}
	}
}

func (proxy *DataSourceProxy) validateRequest() error {
	if !checkWhiteList(proxy.ctx, proxy.targetUrl.Host) {
		return errors.New("target URL is not a valid target")
	}

	if proxy.ds.Type == models.DS_PROMETHEUS {
		if proxy.ctx.Req.Request.Method == "DELETE" {
			return errors.New("deletes not allowed on proxied Prometheus datasource")
		}
		if proxy.ctx.Req.Request.Method == "PUT" {
			return errors.New("puts not allowed on proxied Prometheus datasource")
		}
		if proxy.ctx.Req.Request.Method == "POST" && !(proxy.proxyPath == "api/v1/query" || proxy.proxyPath == "api/v1/query_range" || proxy.proxyPath == "api/v1/series" || proxy.proxyPath == "api/v1/labels" || proxy.proxyPath == "api/v1/query_exemplars") {
			return errors.New("posts not allowed on proxied Prometheus datasource except on /query, /query_range, /series and /labels")
		}
	}

	if proxy.ds.Type == models.DS_ES {
		logger.Debug("ES datasource: entering validation")

		if proxy.ctx.Req.Request.Method == "DELETE" {
			return errors.New("deletes not allowed on proxied Elasticsearch datasource")
		}
		if proxy.ctx.Req.Request.Method == "PUT" {
			return errors.New("puts not allowed on proxied Elasticsearch datasource")
		}
		if proxy.ctx.Req.Request.Method == "POST" && proxy.proxyPath != "_msearch" {
			return errors.New("posts not allowed on proxied Elasticsearch datasource except on /_msearch")
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

	err := proxy.checkUserTeamDatasourceAccess()
	if err != nil {
		logger.Debug("ES datasource: team access have failed", "error", err)
		return err
	}

	logger.Debug("ES datasource: access is success")

	// found route if there are any
	if len(proxy.plugin.Routes) > 0 {
		for _, route := range proxy.plugin.Routes {
			// method match
			if route.Method != "" && route.Method != "*" && route.Method != proxy.ctx.Req.Method {
				continue
			}

			if route.ReqRole.IsValid() {
				if !proxy.ctx.HasUserRole(route.ReqRole) {
					return errors.New("plugin proxy route access denied")
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
	logger.Debug("Call: validateESMappingIndexTemplate")

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
	logger.Debug("Call: validateESSearchIndexTemplate")

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
		return proxy.ds.Database, "", true
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

// Check if a currently logged in user has access to this datasource
// If any of the user's groups match the list of allowed groups defined
// in this datasource's configuration or there are no allowed groups defined
// the access for the user is granted.
// Returns error or nil if access is allowed
func (proxy *DataSourceProxy) checkUserTeamDatasourceAccess() error {
	logger.Debug("Call: checkUserTeamDatasourceAccess")

	if proxy.ctx.IsAnonymous {
		logger.Debug("Anonymous access is used, check is success")
		return nil
	}

	if proxy.ctx.OrgRole == models.ROLE_ADMIN || proxy.ctx.IsGrafanaAdmin {
		logger.Debug(fmt.Sprintf("User: '%s' is admin, check is success", proxy.ctx.Login))
		return nil
	}

	allowedAll := proxy.ds.JsonData.Get("allowedAll").MustBool(false)
	if allowedAll {
		logger.Debug(fmt.Sprintf("Allow all users is enabled for the datasource: '%s', check is success", proxy.ds.Name))
		return nil
	}

	allowedTeams := proxy.ds.JsonData.Get("allowedTeams").MustString("")
	if len(allowedTeams) == 0 {
		logger.Debug(fmt.Sprintf("There are no allowed teams specified for the datasource: '%s', check is success", proxy.ds.Name))
		return nil
	}

	allowedTeamsList := strings.Split(allowedTeams, ",")
	for i := 0; i < len(allowedTeamsList); i++ {
		allowedTeamsList[i] = strings.TrimSpace(allowedTeamsList[i])
	}

	logger.Debug(fmt.Sprintf("Got allowed teams: '%s' for the datasource: '%s'", strings.Join(allowedTeamsList, ","), proxy.ds.Name))

	userTeams, err := proxy.getUserTeams()
	if err != nil {
		logger.Debug(fmt.Sprintf("Error getting the list of user: '%s' teams", proxy.ctx.Login), "error", err)
		return err
	}

	for _, allowedTeam := range allowedTeamsList {
		if proxy.checkUserHasTeam(userTeams, allowedTeam) {
			logger.Debug(fmt.Sprintf("The allowed team: '%s' of the user: '%s' matches the user team for the datasource: '%s', check is success", allowedTeam, proxy.ctx.Login, proxy.ds.Name))
			return nil
		}
	}

	return errors.New(fmt.Sprintf("The user: '%s' has no access to the datasource: '%s' with allowed teams: '%s'", proxy.ctx.Login, proxy.ds.Name, strings.Join(allowedTeamsList, ",")))
}

// Check if there is a specified team name in the provided list of user's teams
func (proxy *DataSourceProxy) checkUserHasTeam(userTeams []*models.TeamDTO, teamName string) bool {
	for _, userTeam := range userTeams {
		if userTeam.Name == teamName {
			// user has a team with a matching name
			return true
		}
	}
	// no matching teams found
	return false
}

// Get the list of user's teams from the database
func (proxy *DataSourceProxy) getUserTeams() ([]*models.TeamDTO, error) {
	teamsQuery := models.GetTeamsByUserQuery{OrgId: proxy.ctx.OrgId, UserId: proxy.ctx.UserId}
	err := bus.Dispatch(&teamsQuery)
	return teamsQuery.Result, err
}

func (proxy *DataSourceProxy) logRequest() {
	if !setting.DataProxyLogging {
		return
	}

	datasourceAuditEnabled := proxy.ds.JsonData.Get("auditEnabled").MustBool(false)
	dashboardAuditEnabled, err := strconv.ParseBool(proxy.ctx.Req.Header.Get("X-Audit-Enabled"))
	if err != nil {
		dashboardAuditEnabled = false
	}

	// Continue if audit have been enabled by:
	// * Globally set enabled for all dashboards and datasources
	// * Set for this datasource by auditEnabled property
	// * Set for this dashboard by X-Audit-Enabled header
	if !(setting.DataProxyLogAll || datasourceAuditEnabled || dashboardAuditEnabled) {
		return
	}

	// Obtain the http request body and restore the original request body object
	var body string
	if proxy.ctx.Req.Request.Body != nil {
		buffer, err := ioutil.ReadAll(proxy.ctx.Req.Request.Body)
		if err == nil {
			proxy.ctx.Req.Request.Body = ioutil.NopCloser(bytes.NewBuffer(buffer))
			body = string(buffer)
		}
	}

	// Get the dashboard and panel ids form the HTTP headers
	dashboardId := proxy.ctx.Req.Header.Get("X-Dashboard-Id")
	panelId := proxy.ctx.Req.Header.Get("X-Panel-Id")

	// Decode the audit variables if they have been sent
	var dashboardAuditVariablesHeader string
	var dashboardAuditVariables []byte

	dashboardAuditVariablesHeader = proxy.ctx.Req.Header.Get("X-Audit-Variables")
	if dashboardAuditVariablesHeader != "" {
		dashboardAuditVariables, err = base64.StdEncoding.DecodeString(dashboardAuditVariablesHeader)
		if err != nil {
			logger.Error("Could not decode the audit variables! Got header: " + dashboardAuditVariablesHeader)
			dashboardAuditVariables = nil
		}
	} else {
		dashboardAuditVariables = nil
	}

	// Clean up the audit headers to prevent passing them to the datasource backend
	proxy.ctx.Req.Header.Del("X-Audit-Variables")
	proxy.ctx.Req.Header.Del("X-Audit-Enabled")

	if setting.DataProxyLogJSON {

		type ProxyRequestRecord struct {
			OrgID          int64       `json:"org_id"`
			UserId         int64       `json:"user_id"`
			Username       string      `json:"username"`
			DatasourceType string      `json:"datasource_type"`
			DatasourceName string      `json:"datasource_name"`
			Method         string      `json:"method"`
			Uri            string      `json:"uri"`
			Referer        string      `json:"referer"`
			DashboardId    string      `json:"dashboard_id"`
			PanelId        string      `json:"panel_id"`
			Variables      interface{} `json:"variables"`
			Body           string      `json:"body"`
		}

		requestRecord := ProxyRequestRecord{
			OrgID:          proxy.ctx.OrgId,
			UserId:         proxy.ctx.OrgId,
			Username:       proxy.ctx.Login,
			DatasourceType: proxy.ds.Type,
			DatasourceName: proxy.ds.Name,
			Method:         proxy.ctx.Req.Request.Method,
			Uri:            proxy.ctx.Req.RequestURI,
			Referer:        proxy.ctx.Req.Request.Referer(),
			DashboardId:    dashboardId,
			PanelId:        panelId,
			Body:           body,
		}

		if dashboardAuditVariables != nil {
			err = json.Unmarshal(dashboardAuditVariables, &requestRecord.Variables)
			if err != nil {
				logger.Error("Could not parse the audit variables! Got header: " + string(dashboardAuditVariables))
				requestRecord.Variables = nil
			}
		} else {
			requestRecord.Variables = nil
		}

		requestRecordString, _ := json.Marshal(requestRecord)

		logger.Info("Proxying incoming request",
			"data",
			base64.StdEncoding.EncodeToString(requestRecordString),
		)

	} else {

		logger.Info("Proxying incoming request",
			"userid", proxy.ctx.UserId,
			"orgid", proxy.ctx.OrgId,
			"username", proxy.ctx.Login,
			"datasource", proxy.ds.Type,
			"name", proxy.ds.Name,
			"uri", proxy.ctx.Req.RequestURI,
			"method", proxy.ctx.Req.Request.Method,
			"referer", proxy.ctx.Req.Request.Referer(),
			"dashboard", dashboardId,
			"panel", panelId,
			"variables", string(dashboardAuditVariables),
			"body", body,
		)

	}

}

func checkWhiteList(c *models.ReqContext, host string) bool {
	if host != "" && len(setting.DataProxyWhiteList) > 0 {
		if _, exists := setting.DataProxyWhiteList[host]; !exists {
			c.JsonApiErr(403, "Data proxy hostname and ip are not included in whitelist", nil)
			return false
		}
	}

	return true
}
