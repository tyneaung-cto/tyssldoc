package checks

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func RunHTTPChecks(ctx context.Context, target Target, timeout time.Duration) HTTPResult {
	res := HTTPResult{
		SecurityHeaders: map[string]string{},
	}

	httpsURL := "https://" + target.Host
	httpURL := "http://" + target.Host

	client := &http.Client{Timeout: timeout}

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, httpsURL, nil)
	httpsResp, err := client.Do(req)
	if err != nil {
		res.Failures = append(res.Failures, "HTTPS request failed: "+err.Error())
	} else {
		defer httpsResp.Body.Close()
		res.HTTPSReachable = true
		res.HTTPSStatusCode = httpsResp.StatusCode
		if httpsResp.Request != nil && httpsResp.Request.URL != nil {
			res.FinalURL = httpsResp.Request.URL.String()
		}

		headers := httpsResp.Header
		res.HSTS = headers.Get("Strict-Transport-Security")
		if res.HSTS == "" {
			res.Warnings = append(res.Warnings, "HSTS header missing")
		}

		captureHeader(res.SecurityHeaders, headers, "Strict-Transport-Security")
		captureHeader(res.SecurityHeaders, headers, "Content-Security-Policy")
		captureHeader(res.SecurityHeaders, headers, "X-Frame-Options")
		captureHeader(res.SecurityHeaders, headers, "X-Content-Type-Options")
		captureHeader(res.SecurityHeaders, headers, "Referrer-Policy")
		captureHeader(res.SecurityHeaders, headers, "Permissions-Policy")

		for k, v := range res.SecurityHeaders {
			if v == "" {
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s header missing", k))
			}
		}
	}

	redirectClient := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	httpReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, httpURL, nil)
	httpResp, err := redirectClient.Do(httpReq)
	if err != nil {
		res.Warnings = append(res.Warnings, "HTTP request check failed: "+err.Error())
	} else {
		defer httpResp.Body.Close()
		if httpResp.Request != nil && httpResp.Request.URL != nil {
			res.HTTPRedirectsHTTPS = strings.EqualFold(httpResp.Request.URL.Scheme, "https")
		}
		if !res.HTTPRedirectsHTTPS {
			res.Warnings = append(res.Warnings, "HTTP does not redirect to HTTPS")
		}
	}

	return res
}

func captureHeader(dst map[string]string, h http.Header, key string) {
	dst[strings.ToLower(key)] = h.Get(key)
}
