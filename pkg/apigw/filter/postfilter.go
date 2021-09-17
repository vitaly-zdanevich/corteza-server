package filter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/cortezaproject/corteza-server/pkg/apigw/types"
	pe "github.com/cortezaproject/corteza-server/pkg/errors"
)

type (
	redirection struct {
		types.FilterMeta

		location *url.URL
		status   int

		params struct {
			HTTPStatus int    `json:"status,string"`
			Location   string `json:"location"`
		}
	}

	// support for arbitrary response
	// obfuscation
	customResponse struct {
		types.FilterMeta
		params struct {
			Source string `json:"source"`
		}
	}

	defaultJsonResponse struct {
		types.FilterMeta
	}
)

func NewRedirection() (e *redirection) {
	e = &redirection{}

	e.Name = "redirection"
	e.Label = "Redirection"
	e.Kind = types.PostFilter

	e.Args = []*types.FilterMetaArg{
		{
			Type:    "status",
			Label:   "status",
			Options: map[string]interface{}{},
		},
		{
			Type:    "text",
			Label:   "location",
			Options: map[string]interface{}{},
		},
	}

	return
}

func (r redirection) String() string {
	return fmt.Sprintf("apigw filter %s (%s)", r.Name, r.Label)
}

func (r redirection) Meta() types.FilterMeta {
	return r.FilterMeta
}

func (r redirection) Weight() int {
	return r.Wgt
}

func (r *redirection) Merge(params []byte) (types.Handler, error) {
	err := json.NewDecoder(bytes.NewBuffer(params)).Decode(&r.params)

	loc, err := url.ParseRequestURI(r.params.Location)

	if err != nil {
		return nil, fmt.Errorf("could not validate parameters, invalid URL: %s", err)
	}

	if !checkStatus("redirect", r.params.HTTPStatus) {
		return nil, fmt.Errorf("could not validate parameters, wrong status %d", r.params.HTTPStatus)
	}

	r.location = loc
	r.status = r.params.HTTPStatus

	return r, err
}

func (r redirection) Handler() types.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) error {
		http.Redirect(rw, req, r.location.String(), r.status)
		return nil
	}
}

func NewDefaultJsonResponse() (e *defaultJsonResponse) {
	e = &defaultJsonResponse{}

	e.Name = "defaultJsonResponse"
	e.Label = "Default JSON response"
	e.Kind = types.PostFilter

	return
}

func (j defaultJsonResponse) String() string {
	return fmt.Sprintf("apigw filter %s (%s)", j.Name, j.Label)
}

func (j defaultJsonResponse) Meta() types.FilterMeta {
	return j.FilterMeta
}

func (j *defaultJsonResponse) Merge(params []byte) (h types.Handler, err error) {
	return j, err
}

func (j defaultJsonResponse) Handler() types.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) error {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusAccepted)

		if _, err := rw.Write([]byte(`{}`)); err != nil {
			return pe.Internal("could not write to body: (%v)", err)
		}

		return nil
	}
}

func checkStatus(typ string, status int) bool {
	switch typ {
	case "redirect":
		return status >= 300 && status <= 399
	default:
		return true
	}
}
