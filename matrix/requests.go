package matrix

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/t2bot/matrix-media-repo/common/config"
	"github.com/t2bot/matrix-media-repo/common/rcontext"
)

const NoSigningKey = ""

// Based in part on https://github.com/matrix-org/gomatrix/blob/072b39f7fa6b40257b4eead8c958d71985c28bdd/client.go#L180-L243
func doRequest(ctx rcontext.RequestContext, method string, urlStr string, body interface{}, result interface{}, accessToken string, ipAddr string) error {
	ctx.Log.Debugf("Calling %s %s", method, urlStr)
	var bodyBytes []byte
	if body != nil {
		jsonStr, err := json.Marshal(body)
		if err != nil {
			return err
		}

		bodyBytes = jsonStr
	}

	req, err := http.NewRequest(method, urlStr, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return err
	}

	req.Header.Set("User-Agent", "matrix-media-repo")
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	if ipAddr != "" {
		req.Header.Set("X-Forwarded-For", ipAddr)
		req.Header.Set("X-Real-IP", ipAddr)
	}

	// Note: We don't use the matrix.NewHttpClient (safeClient) here because the URL is controlled by the
	// operator already. The URL should therefore be trusted as safe.
	client := &http.Client{
		Timeout: time.Duration(ctx.Config.TimeoutSeconds.ClientServer) * time.Second,
	}
	res, err := client.Do(req)
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return err
	}

	contents, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK {
		mtxErr := &ErrorResponse{}
		err = json.Unmarshal(contents, mtxErr)
		if err == nil && mtxErr.ErrorCode != "" {
			return mtxErr
		}
		return errors.New("failed to perform request: " + string(contents))
	}

	if result != nil {
		err = json.Unmarshal(contents, &result)
		if err != nil {
			return err
		}
	}

	return nil
}

func FederatedGet(ctx rcontext.RequestContext, reqUrl string, realHost string, destination string, useSigningKeyPath string, followRedirects bool) (*http.Response, error) {
	ctx.Log.Debug("Doing federated GET to " + reqUrl + " with host " + realHost)

	cb := getFederationBreaker(realHost)

	var resp *http.Response
	replyError := cb.CallContext(ctx, func() error {
		req, err := http.NewRequest(http.MethodGet, reqUrl, nil)
		if err != nil {
			return err
		}

		// Override the host to be compliant with the spec
		req.Header.Set("Host", realHost)
		req.Header.Set("User-Agent", "matrix-media-repo")
		req.Host = realHost

		if useSigningKeyPath != NoSigningKey {
			ctx.Log.Debug("Reading signing key and adding authentication headers")
			key, err := getLocalSigningKey(useSigningKeyPath)
			if err != nil {
				return err
			}
			parsed, err := url.Parse(reqUrl)
			if err != nil {
				return err
			}
			auth, err := CreateXMatrixHeader(ctx.Request.Host, destination, http.MethodGet, parsed.RequestURI(), nil, key.Key, key.Version)
			if err != nil {
				return err
			}
			req.Header.Set("Authorization", auth)
		}

		// strip port first, certs are port-insensitive
		h, _, err := net.SplitHostPort(realHost)
		if err == nil {
			realHost = h
		} else {
			ctx.Log.Warn("Non-fatal error parsing host:port for federation:", err)
		}

		client := NewHttpClient(ctx, &HttpClientConfig{
			Timeout:                time.Duration(ctx.Config.TimeoutSeconds.Federation) * time.Second,
			AllowUnsafeCertificate: os.Getenv("MEDIA_REPO_UNSAFE_FEDERATION") == "true",
			TLSServerName:          realHost,
			AllowedCIDRs:           config.Get().Federation.AllowedNetworks,
			DeniedCIDRs:            config.Get().Federation.DisallowedNetworks,
			FollowRedirects:        followRedirects,
		})

		resp, err = client.Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
			b, _ := io.ReadAll(resp.Body)
			ctx.Log.Warn(string(b))
			return fmt.Errorf("response not ok: %d", resp.StatusCode)
		}
		return nil
	}, 1*time.Minute)

	return resp, replyError
}
