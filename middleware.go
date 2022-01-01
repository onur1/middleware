package middleware

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	validation "github.com/go-ozzo/ozzo-validation"
	"github.com/gorilla/mux"
	"github.com/gorilla/schema"
	"github.com/onur1/middleware/accepts"
)

// MIME types.
const (
	MediaTypeApplicationXML         = "application/xml"
	MediaTypeApplicationJSON        = "application/json"
	MediaTypeFormURLEncoded         = "application/x-www-form-urlencoded"
	MediaTypeImageGIF               = "image/gif"
	MediaTypeImageJPEG              = "image/jpeg"
	MediaTypeImagePNG               = "image/png"
	MediaTypeApplicationOctetStream = "application/octet-stream"
	MediaTypeTextHTML               = "text/html"
	MediaTypeTextXML                = "text/xml"
	MediaTypeTextCSV                = "text/csv"
	MediaTypeTextPlain              = "text/plain"
	MediaTypeMultipartFormData      = "multipart/form-data"
)

var (
	contentTypeHeaderKey      = "Content-Type"
	contentLengthHeaderKey    = "Content-Length"
	contentTypeJSON           = MediaTypeApplicationJSON
	contentTypeHTML           = MediaTypeTextHTML
	offeredContentTypes       = []string{contentTypeHTML, contentTypeJSON}
	defaultAcceptsContentType = MediaTypeApplicationJSON
)

// ContentType adds the Content-Type header.
func (m *Middleware) ContentType(mediaType string) {
	m.Header(contentTypeHeaderKey, mediaType)
}

// Status sets the response status code.
func (m *Middleware) Status(status int) {
	m.responseWriter.WriteHeader(status)
}

// Header sets a header on the response.
// Note that, changing a header after a call to WriteHeader has no effect.
func (m *Middleware) Header(name, value string) {
	m.responseWriter.Header().Set(name, value)
}

// Cookie sets a secure cookie with the provided encryption key.
func (m *Middleware) Cookie(b []byte, opts *http.Cookie, blockKey []byte) error {
	var out []byte

	if blockKey != nil {
		block, err := aes.NewCipher(blockKey)
		if err != nil {
			return fmt.Errorf("middleware: %s: %v", opts.Name, err)
		}

		out, err = encrypt(block, b)
		if err != nil {
			return fmt.Errorf("middleware: %s: %v", opts.Name, err)
		}
	}

	value := base64.URLEncoding.EncodeToString(out)

	http.SetCookie(m.responseWriter, &http.Cookie{
		Name:     opts.Name,
		Value:    value,
		Path:     opts.Path,
		Domain:   opts.Domain,
		MaxAge:   opts.MaxAge,
		Secure:   opts.Secure,
		HttpOnly: opts.HttpOnly,
		SameSite: opts.SameSite,
	})

	return nil
}

// Send sends the given byte array response without
// specifying the Content-Type.
func (m *Middleware) Send(body []byte, code int) error {
	// Note that, the Content-Length header is always appended,
	// this is required for drawing the download progress bar.
	m.Header(contentLengthHeaderKey, strconv.Itoa(len(body)))

	m.Status(code)

	_, err := m.responseWriter.Write(body)
	if err != nil {
		return fmt.Errorf("send: %w", err)
	}

	return nil
}

// SendJSON sends a JSON object as response.
// Content-Type header will be set to application/json.
func (m *Middleware) SendJSON(data interface{}, code int) error {
	body, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("json: %w", err)
	}

	m.ContentType(MediaTypeApplicationJSON)

	sendErr := m.Send(body, code)
	if sendErr != nil {
		return sendErr
	}

	return nil
}

// SendPlainText sends a string as response.
// Content-Type header will be set to text/plain.
func (m *Middleware) SendPlainText(s string, code int) error {
	m.ContentType(MediaTypeTextPlain)

	sendErr := m.Send([]byte(s), code)
	if sendErr != nil {
		return sendErr
	}

	return nil
}

// SendHTML sends a string as HTML response.
// Content-Type header will be set to text/html.
func (m *Middleware) SendHTML(s string, code int) error {
	m.ContentType(MediaTypeTextHTML)

	sendErr := m.Send([]byte(s), code)
	if sendErr != nil {
		return sendErr
	}

	return nil
}

type httpErr interface {
	Status() int
}

// Destroy ends the response with an error.
//
// When a Middleware error conforms to httpErr interface,
// this method will set the status code to the output of Status() on this error,
// by default the returned status code will be 500.
//
// Error responses are in JSON, if for some reason a JSON object couldn't
// be serialized, this function will simply write the error to stdout.
func (m *Middleware) Destroy(err error) {
	var status int

	switch e := err.(type) {
	case httpErr:
		status = e.Status()
	default:
		status = http.StatusInternalServerError
	}

	sendErr := m.SendJSON(err, status)
	if sendErr != nil {
		fmt.Println(fmt.Errorf("middleware: %w", sendErr).Error())
	}
}

// Redirect redirects this request to the given URL with the given 3xx code.
func (m *Middleware) Redirect(url string, code int) {
	http.Redirect(m.responseWriter, m.request, url, code)
}

func (m *Middleware) NegotiateContentEncoding(offers []string) string {
	return accepts.NegotiateContentEncoding(m.request, offers)
}

func (m *Middleware) NegotiateContentType(offers []string, defaultOffer string) string {
	return accepts.NegotiateContentType(m.request, offers, defaultOffer)
}

func (m *Middleware) AcceptsHTML() bool {
	return m.request.Header.Get(contentTypeHeaderKey) != contentTypeJSON &&
		m.NegotiateContentType(
			offeredContentTypes,
			defaultAcceptsContentType,
		) == contentTypeHTML
}

func (m *Middleware) GetRequest() *http.Request {
	return m.request
}

func (m *Middleware) GetResponseWriter() http.ResponseWriter {
	return m.responseWriter
}

//
// decode
//

var decoder = schema.NewDecoder()

func init() {
	decoder.IgnoreUnknownKeys(true)
	decoder.SetAliasTag("json")
}

func validateString(s string, rules ...validation.Rule) (string, error) {
	a := strings.TrimSpace(s)

	err := validation.Validate(a, rules...)
	if err != nil {
		return a, err
	}

	return a, nil
}

func (m *Middleware) ValidateHeader(name string, rules ...validation.Rule) (string, error) {
	return validateString(m.request.Header.Get(name), rules...)
}

func (m *Middleware) ValidateParam(name string, rules ...validation.Rule) (string, error) {
	return validateString(mux.Vars(m.request)[name], rules...)
}

func (m *Middleware) ValidateCookie(name string, rules ...validation.Rule) (string, error) {
	q, err := m.request.Cookie(name)
	if err != nil {
		return "", err
	}

	return validateString(q.Value, rules...)
}

func (m *Middleware) DecodeQuery(dst validation.Validatable) error {
	q, err := url.ParseQuery(m.request.URL.RawQuery)
	if err != nil {
		return err
	}

	err = decoder.Decode(dst, q)
	if err != nil {
		return err
	}

	err = validation.Validate(dst)
	if err != nil {
		return err
	}

	return nil
}

func (m *Middleware) DecodeBody(dst validation.Validatable) error {
	contentType := m.request.Header.Get("Content-Type")

	var err error

	switch contentType {
	case MediaTypeFormURLEncoded:
		err = m.request.ParseForm()
		if err != nil {
			return err
		}

		err = decoder.Decode(dst, m.request.PostForm)
		if err != nil {
			return err
		}
	case MediaTypeApplicationJSON:
		err = json.NewDecoder(m.request.Body).Decode(dst)
		if err != nil {
			return err
		}
	default:
		return errors.New("unknown content-type")
	}

	err = validation.Validate(dst)
	if err != nil {
		return err
	}

	return nil
}

func (m *Middleware) DecodeBoolParam(name string, rules ...validation.Rule) (bool, error) {
	a, err := m.ValidateParam(name, rules...)
	if err != nil {
		return false, err
	}

	b, err := strconv.ParseBool(a)
	if err != nil {
		return false, err
	}

	return b, nil
}

func (m *Middleware) DecodeFloatParam(name string, rules ...validation.Rule) (float64, error) {
	a, err := m.ValidateParam(name, rules...)
	if err != nil {
		return 0, err
	}

	b, err := strconv.ParseFloat(a, 64)
	if err != nil {
		return 0, err
	}

	return b, nil
}

func (m *Middleware) DecodeIntParam(name string, rules ...validation.Rule) (int64, error) {
	a, err := m.ValidateParam(name, rules...)
	if err != nil {
		return 0, err
	}

	b, err := strconv.ParseInt(a, 0, 10)
	if err != nil {
		return 0, err
	}

	return b, nil
}

func (m *Middleware) DecodeUintParam(name string, rules ...validation.Rule) (uint64, error) {
	a, err := m.ValidateParam(name, rules...)
	if err != nil {
		return 0, err
	}

	b, err := strconv.ParseUint(a, 10, 0)
	if err != nil {
		return 0, err
	}

	return b, nil
}

type Middleware struct {
	request        *http.Request
	responseWriter http.ResponseWriter
}

func NewMiddleware(w http.ResponseWriter, r *http.Request) *Middleware {
	m := &Middleware{
		request:        r,
		responseWriter: w,
	}

	return m
}

func random(length int) ([]byte, error) {
	k := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil, err
	}
	return k, nil
}

var ErrGenerateIV = errors.New("middleware: could not generate the encryption iv")

func encrypt(block cipher.Block, value []byte) ([]byte, error) {
	iv, err := random(block.BlockSize())
	if err != nil {
		return nil, ErrGenerateIV
	}

	if iv == nil {
		return nil, ErrGenerateIV
	}

	s := cipher.NewCTR(block, iv)
	s.XORKeyStream(value, value)

	return append(iv, value...), nil
}
