package input

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/hunter-0x7/Lfi-and-Path-traversal-Fuzzer/pkg/model"
	"github.com/tidwall/gjson"
)

func LoadTargets(singleURL, listPath, requestPath string) ([]model.Target, error) {
	if singleURL != "" {
		target, err := ParseTargetFromURL(singleURL)
		if err != nil {
			return nil, err
		}
		return []model.Target{target}, nil
	}
	if listPath != "" {
		return loadTargetsFromList(listPath)
	}
	if requestPath != "" {
		return loadTargetsFromRaw(requestPath)
	}
	return nil, errors.New("no targets provided")
}

func ParseTargetFromURL(raw string) (model.Target, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return model.Target{}, err
	}
	headers := map[string]string{
		"Accept":     "*/*",
		"User-Agent": "TraversalX",
	}
	params := extractQueryParams(parsed)
	return model.Target{
		ID:      raw,
		URL:     parsed.String(),
		Method:  http.MethodGet,
		Headers: headers,
		Cookies: map[string]string{},
		Params:  params,
		Source:  "url",
	}, nil
}

func loadTargetsFromList(path string) ([]model.Target, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var targets []model.Target
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		target, err := ParseTargetFromURL(line)
		if err != nil {
			return nil, err
		}
		target.Source = "list"
		targets = append(targets, target)
	}
	return targets, scanner.Err()
}

func loadTargetsFromRaw(path string) ([]model.Target, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	requests := splitRawRequests(string(data))
	var targets []model.Target
	for _, raw := range requests {
		target, err := ParseTargetFromRaw(raw)
		if err != nil {
			return nil, err
		}
		targets = append(targets, target)
	}
	return targets, nil
}

func ParseTargetFromRaw(raw string) (model.Target, error) {
	reader := bufio.NewReader(strings.NewReader(raw))
	req, err := http.ReadRequest(reader)
	if err != nil {
		return model.Target{}, err
	}
	body, _ := readRequestBody(req)
	targetURL := req.URL.String()
	if !strings.HasPrefix(targetURL, "http") {
		scheme := "http"
		if strings.HasSuffix(req.Proto, "2.0") {
			scheme = "https"
		}
		targetURL = scheme + "://" + req.Host + targetURL
	}
	headers := map[string]string{}
	for key, values := range req.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}
	cookies := map[string]string{}
	for _, cookie := range req.Cookies() {
		cookies[cookie.Name] = cookie.Value
	}
	params := extractParamsFromRequest(req, body)
	return model.Target{
		ID:       targetURL,
		URL:      targetURL,
		Method:   req.Method,
		Headers:  headers,
		Cookies:  cookies,
		Body:     body,
		Params:   params,
		Source:   "raw",
		RawInput: raw,
	}, nil
}

func readRequestBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}
	defer req.Body.Close()
	return io.ReadAll(req.Body)
}

func splitRawRequests(content string) []string {
	chunks := strings.Split(content, "\n\n")
	var requests []string
	for _, chunk := range chunks {
		if strings.TrimSpace(chunk) == "" {
			continue
		}
		requests = append(requests, strings.TrimSpace(chunk))
	}
	return requests
}

func extractQueryParams(parsed *url.URL) []model.Parameter {
	query := parsed.Query()
	var params []model.Parameter
	for key, values := range query {
		if len(values) == 0 {
			continue
		}
		params = append(params, model.Parameter{
			Name:     key,
			Value:    values[0],
			Location: model.ParamQuery,
		})
	}
	return params
}

func extractParamsFromRequest(req *http.Request, body []byte) []model.Parameter {
	params := extractQueryParams(req.URL)
	contentType := req.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") && len(body) > 0 {
		params = append(params, extractJSONParams(body)...)
	} else if strings.Contains(contentType, "application/x-www-form-urlencoded") && len(body) > 0 {
		if parsed, err := url.ParseQuery(string(body)); err == nil {
			for key, values := range parsed {
				if len(values) == 0 {
					continue
				}
				params = append(params, model.Parameter{
					Name:     key,
					Value:    values[0],
					Location: model.ParamBody,
				})
			}
		}
	} else if strings.Contains(contentType, "multipart/form-data") && len(body) > 0 {
		params = append(params, extractMultipartParams(contentType, body)...)
	}
	return params
}

func extractJSONParams(body []byte) []model.Parameter {
	result := gjson.ParseBytes(body)
	var params []model.Parameter
	result.ForEach(func(key, value gjson.Result) bool {
		params = append(params, model.Parameter{
			Name:     key.String(),
			Value:    value.String(),
			Location: model.ParamJSON,
		})
		return true
	})
	return params
}

func extractMultipartParams(contentType string, body []byte) []model.Parameter {
	parts := strings.Split(contentType, "boundary=")
	if len(parts) < 2 {
		return nil
	}
	boundary := parts[1]
	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	var params []model.Parameter
	for {
		part, err := reader.NextPart()
		if err != nil {
			break
		}
		name := part.FormName()
		if name == "" {
			continue
		}
		value, _ := io.ReadAll(part)
		params = append(params, model.Parameter{
			Name:     name,
			Value:    string(value),
			Location: model.ParamBody,
		})
	}
	return params
}
