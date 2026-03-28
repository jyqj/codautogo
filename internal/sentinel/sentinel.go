package sentinel

import (
	cryptoRand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"time"
)

const (
	DefaultMaxAttempts = 500000
	DefaultErrorPrefix = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"
)

type Request struct {
	Mode             string `json:"mode"`
	DeviceID         string `json:"device_id"`
	SID              string `json:"sid"`
	RequirementsSeed string `json:"requirements_seed"`
	Seed             string `json:"seed"`
	Difficulty       string `json:"difficulty"`
	UserAgent        string `json:"user_agent"`
	MaxAttempts      int    `json:"max_attempts"`
	ErrorPrefix      string `json:"error_prefix"`
}

type Response struct {
	Token     string `json:"token,omitempty"`
	Attempts  int    `json:"attempts,omitempty"`
	ElapsedMS int64  `json:"elapsed_ms,omitempty"`
	Error     string `json:"error,omitempty"`
}

type Generator struct {
	DeviceID         string
	SID              string
	RequirementsSeed string
	UserAgent        string
	MaxAttempts      int
	ErrorPrefix      string
}

func NewGenerator(deviceID, userAgent string) *Generator {
	if deviceID == "" {
		deviceID = newUUID()
	}
	return &Generator{
		DeviceID:         deviceID,
		SID:              newUUID(),
		RequirementsSeed: fmt.Sprintf("%.16f", rand.Float64()),
		UserAgent:        userAgent,
		MaxAttempts:      DefaultMaxAttempts,
		ErrorPrefix:      DefaultErrorPrefix,
	}
}

func (g *Generator) request(mode, seed, difficulty string) Request {
	maxAttempts := g.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = DefaultMaxAttempts
	}
	errorPrefix := g.ErrorPrefix
	if errorPrefix == "" {
		errorPrefix = DefaultErrorPrefix
	}
	return Request{
		Mode:             mode,
		DeviceID:         g.DeviceID,
		SID:              g.SID,
		RequirementsSeed: g.RequirementsSeed,
		Seed:             seed,
		Difficulty:       difficulty,
		UserAgent:        g.UserAgent,
		MaxAttempts:      maxAttempts,
		ErrorPrefix:      errorPrefix,
	}
}

func (g *Generator) GenerateRequirementsToken() string {
	resp, _ := Run(g.request("requirements", "", ""))
	return resp.Token
}

func (g *Generator) GenerateToken(seed, difficulty string) string {
	resp, _ := Run(g.request("pow", seed, difficulty))
	return resp.Token
}

func Run(req Request) (Response, error) {
	if req.Mode == "" {
		req.Mode = "pow"
	}
	if req.DeviceID == "" {
		req.DeviceID = newUUID()
	}
	if req.SID == "" {
		req.SID = newUUID()
	}
	if req.RequirementsSeed == "" {
		req.RequirementsSeed = fmt.Sprintf("%.16f", rand.Float64())
	}
	if req.MaxAttempts <= 0 {
		req.MaxAttempts = DefaultMaxAttempts
	}
	if req.ErrorPrefix == "" {
		req.ErrorPrefix = DefaultErrorPrefix
	}

	switch req.Mode {
	case "requirements":
		token := generateRequirementsToken(req)
		return Response{Token: token, Attempts: 1, ElapsedMS: 0}, nil
	case "pow":
		seed := req.Seed
		if seed == "" {
			seed = req.RequirementsSeed
		}
		difficulty := req.Difficulty
		if difficulty == "" {
			difficulty = "0"
		}
		token, attempts, elapsed := generateToken(req, seed, difficulty)
		return Response{Token: token, Attempts: attempts, ElapsedMS: elapsed}, nil
	default:
		return Response{}, fmt.Errorf("unsupported mode: %s", req.Mode)
	}
}

func generateRequirementsToken(req Request) string {
	config := buildConfig(req)
	config[3] = 1
	config[9] = rand.Intn(46) + 5
	return "gAAAAAC" + base64Encode(config)
}

func generateToken(req Request, seed, difficulty string) (string, int, int64) {
	start := time.Now()
	config := buildConfig(req)
	for i := 0; i < req.MaxAttempts; i++ {
		if result, ok := runCheck(start, seed, difficulty, config, i); ok {
			return "gAAAAAB" + result, i + 1, time.Since(start).Milliseconds()
		}
	}
	return "gAAAAAB" + req.ErrorPrefix + base64Encode("None"), req.MaxAttempts, time.Since(start).Milliseconds()
}

func buildConfig(req Request) []interface{} {
	now := time.Now().UTC()
	dateStr := now.Format("Mon Jan 02 2006 15:04:05 GMT+0000 (Coordinated Universal Time)")
	perfNow := randFloat(1000, 50000)
	timeOrigin := float64(time.Now().UnixNano())/1e6 - perfNow

	navProps := []string{
		"vendorSub", "productSub", "vendor", "maxTouchPoints",
		"scheduling", "userActivation", "doNotTrack", "geolocation",
		"connection", "plugins", "mimeTypes", "pdfViewerEnabled",
		"webkitTemporaryStorage", "webkitPersistentStorage",
		"hardwareConcurrency", "cookieEnabled", "credentials",
		"mediaDevices", "permissions", "locks", "ink",
	}
	docKeys := []string{"location", "implementation", "URL", "documentURI", "compatMode"}
	winKeys := []string{"Object", "Function", "Array", "Number", "parseFloat", "undefined"}
	hardwareOptions := []int{4, 8, 12, 16}

	navProp := navProps[rand.Intn(len(navProps))]
	return []interface{}{
		"1920x1080",
		dateStr,
		4294705152,
		rand.Float64(),
		req.UserAgent,
		"https://sentinel.openai.com/sentinel/20260124ceb8/sdk.js",
		nil,
		nil,
		"en-US",
		"en-US,en",
		rand.Float64(),
		navProp + "−undefined",
		docKeys[rand.Intn(len(docKeys))],
		winKeys[rand.Intn(len(winKeys))],
		perfNow,
		req.SID,
		"",
		hardwareOptions[rand.Intn(len(hardwareOptions))],
		timeOrigin,
	}
}

func runCheck(start time.Time, seed, difficulty string, config []interface{}, nonce int) (string, bool) {
	config[3] = nonce
	config[9] = int(math.Round(float64(time.Since(start).Milliseconds())))
	data := base64Encode(config)
	hashHex := fnv1a32(seed + data)
	diffLen := len(difficulty)
	if diffLen > len(hashHex) {
		diffLen = len(hashHex)
	}
	if diffLen == 0 || hashHex[:diffLen] <= difficulty {
		return data + "~S", true
	}
	return "", false
}

func base64Encode(v any) string {
	raw, _ := json.Marshal(v)
	return base64.StdEncoding.EncodeToString(raw)
}

func fnv1a32(text string) string {
	var h uint32 = 2166136261
	for _, ch := range text {
		h ^= uint32(ch)
		h *= 16777619
	}
	h ^= h >> 16
	h *= 2246822507
	h ^= h >> 13
	h *= 3266489909
	h ^= h >> 16
	return fmt.Sprintf("%08x", h)
}

func randFloat(min, max float64) float64 {
	return min + rand.Float64()*(max-min)
}

func newUUID() string {
	b := make([]byte, 16)
	if _, err := cryptoRand.Read(b); err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	buf := make([]byte, 36)
	hex.Encode(buf[0:8], b[0:4])
	buf[8] = '-'
	hex.Encode(buf[9:13], b[4:6])
	buf[13] = '-'
	hex.Encode(buf[14:18], b[6:8])
	buf[18] = '-'
	hex.Encode(buf[19:23], b[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:36], b[10:16])
	return string(buf)
}
