package system

import (
	"github.com/cortezaproject/corteza-server/pkg/id"
	"net/http"
	"testing"

	"github.com/cortezaproject/corteza-server/tests/helpers"
)

func TestAuthImpersonate(t *testing.T) {
	h := newHelper(t)

	input := &struct {
		UserID uint64 `json:",string"`
	}{
		UserID: id.Next(),
	}

	h.apiInit().
		Post("/auth/impersonate").
		Header("Accept", "application/json").
		JSON(helpers.JSON(input)).
		Expect(t).
		Status(http.StatusOK).
		Assert(helpers.AssertNoErrors).
		End()

	//res := h.lookupAuthClientByHandle(handle)
	//h.a.NotNil(res)
	//h.a.Equal(handle, res.Handle)
}
