package notifications

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/context/ctxhttp"

	"github.com/grafana/grafana/pkg/util"
)

type Webhook struct {
	Url         string
	User        string
	Password    string
	Body        string
	HttpMethod  string
	HttpHeader  map[string]string
	ContentType string
	ProxyUrl    string
}

func getProxyFunction(webhook *Webhook) func(*http.Request) (*url.URL, error) {
	if webhook.ProxyUrl != "" {
		proxyUrl, err := url.Parse(webhook.ProxyUrl)
		if err != nil {
			return http.ProxyFromEnvironment
		} else {
			return http.ProxyURL(proxyUrl)
		}
	} else {
		return http.ProxyFromEnvironment
	}
}

func getHttpClient(webhook *Webhook) *http.Client {
	var netTransport = &http.Transport{
		TLSClientConfig: &tls.Config{
			Renegotiation: tls.RenegotiateFreelyAsClient,
		},
		Proxy: getProxyFunction(webhook),
		Dial: (&net.Dialer{
			Timeout: 30 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 5 * time.Second,
	}

	var netClient = &http.Client{
		Timeout:   time.Second * 30,
		Transport: netTransport,
	}

	return netClient
}

func (ns *NotificationService) sendWebRequestSync(ctx context.Context, webhook *Webhook) error {
	ns.log.Debug("Sending webhook", "url", webhook.Url, "http method", webhook.HttpMethod, "ProxyUrl", webhook.ProxyUrl)

	if webhook.HttpMethod == "" {
		webhook.HttpMethod = http.MethodPost
	}

	if webhook.HttpMethod != http.MethodPost && webhook.HttpMethod != http.MethodPut {
		return fmt.Errorf("webhook only supports HTTP methods PUT or POST")
	}

	request, err := http.NewRequest(webhook.HttpMethod, webhook.Url, bytes.NewReader([]byte(webhook.Body)))
	if err != nil {
		return err
	}

	if webhook.ContentType == "" {
		webhook.ContentType = "application/json"
	}

	request.Header.Add("Content-Type", webhook.ContentType)
	request.Header.Add("User-Agent", "Grafana")

	if webhook.User != "" && webhook.Password != "" {
		request.Header.Add("Authorization", util.GetBasicAuthHeader(webhook.User, webhook.Password))
	}

	for k, v := range webhook.HttpHeader {
		request.Header.Set(k, v)
	}

	netClient := getHttpClient(webhook)

	resp, err := ctxhttp.Do(ctx, netClient, request)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode/100 == 2 {
		ns.log.Debug("Webhook succeeded", "url", webhook.Url, "statuscode", resp.Status)
		// flushing the body enables the transport to reuse the same connection
		if _, err := io.Copy(ioutil.Discard, resp.Body); err != nil {
			ns.log.Error("Failed to copy resp.Body to ioutil.Discard", "err", err)
		}
		return nil
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	ns.log.Debug("Webhook failed", "url", webhook.Url, "statuscode", resp.Status, "body", string(body))
	return fmt.Errorf("Webhook response status %v", resp.Status)
}
