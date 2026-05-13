package model

import "time"

type ParamLocation string

const (
	ParamQuery   ParamLocation = "query"
	ParamBody    ParamLocation = "body"
	ParamJSON    ParamLocation = "json"
	ParamHeader  ParamLocation = "header"
	ParamCookie  ParamLocation = "cookie"
	ParamUnknown ParamLocation = "unknown"
)

type Parameter struct {
	Name     string
	Value    string
	Location ParamLocation
}

type Target struct {
	ID       string
	URL      string
	Method   string
	Headers  map[string]string
	Cookies  map[string]string
	Body     []byte
	Params   []Parameter
	Source   string
	RawInput string
}

type SignatureMatch struct {
	Name     string
	Category string
	Excerpt  string
}

type Evidence struct {
	StatusCode int
	Length     int
	Duration   time.Duration
	Snippet    string
	Hash       string
}

type Finding struct {
	TargetURL      string
	Parameter      string
	Location       ParamLocation
	Method         string
	Payload        string
	Signatures     []SignatureMatch
	Reason         string
	Severity       string
	Confidence     int
	CWE            string
	CVSS           string
	Remediation    string
	Reproduction   []string
	Evidence       Evidence
	FirstObserved  time.Time
	LastValidated  time.Time
	VerificationID string
}

type ScanStats struct {
	TotalTargets   int
	TotalParams    int
	TotalPayloads  int
	RequestsSent   int
	Findings       int
	Errors         int
	StartTime      time.Time
	LastUpdateTime time.Time
}
