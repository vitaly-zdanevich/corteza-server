package handlers

/*
	Hello! This file is auto-generated from `docs/src/spec.json`.

	For development:
	In order to update the generated files, edit this file under the location,
	add your struct fields, imports, API definitions and whatever you want, and:

	1. run [spec](https://github.com/titpetric/spec) in the same folder,
	2. run `./_gen.php` in this folder.

	You may edit `notification.go`, `notification.util.go` or `notification_test.go` to
	implement your API calls, helper functions and tests. The file `notification.go`
	is only generated the first time, and will not be overwritten if it exists.
*/

import (
	"context"
	"github.com/go-chi/chi"
	"net/http"

	"github.com/titpetric/factory/resputil"

	"github.com/crusttech/crust/crm/rest/request"
)

// Internal API interface
type NotificationAPI interface {
	EmailSend(context.Context, *request.NotificationEmailSend) (interface{}, error)
}

// HTTP API interface
type Notification struct {
	EmailSend func(http.ResponseWriter, *http.Request)
}

func NewNotification(nh NotificationAPI) *Notification {
	return &Notification{
		EmailSend: func(w http.ResponseWriter, r *http.Request) {
			defer r.Body.Close()
			params := request.NewNotificationEmailSend()
			resputil.JSON(w, params.Fill(r), func() (interface{}, error) {
				return nh.EmailSend(r.Context(), params)
			})
		},
	}
}

func (nh *Notification) MountRoutes(r chi.Router, middlewares ...func(http.Handler) http.Handler) {
	r.Group(func(r chi.Router) {
		r.Use(middlewares...)
		r.Route("/notification", func(r chi.Router) {
			r.Post("/email", nh.EmailSend)
		})
	})
}