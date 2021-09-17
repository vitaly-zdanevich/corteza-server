package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/cortezaproject/corteza-server/pkg/id"
	//"github.com/cortezaproject/corteza-server/store"
	"github.com/cortezaproject/corteza-server/system/types"
	"time"
)

type (
	ExtraReqInfo struct {
		RemoteAddr string
		UserAgent  string
	}
)

func (t *token) Generate(ctx context.Context, s tokenStore, i Identifiable) (tokenString string, err error) {
	var (
		eti  = GetExtraReqInfoFromContext(ctx)
		oa2t = &types.AuthOa2token{
			ID:         id.Next(),
			CreatedAt:  time.Now().Round(time.Second),
			RemoteAddr: eti.RemoteAddr,
			UserAgent:  eti.UserAgent,
		}

		acc = &types.AuthConfirmedClient{
			ConfirmedAt: oa2t.CreatedAt,
		}

		//tgr = oauth2.TokenGenerateRequest{}
	)

	tokenString = t.Encode(i)
	oa2t.Access = tokenString
	// @todo: set expiry
	//oa2t.ExpiresAt =

	// @todo?: refresh; since we will be saving it now so
	//oa2t.Refresh = string(rand.Bytes(48))
	//oa2t.ExpiresAt =

	if oa2t.Data, err = json.Marshal(oa2t); err != nil {
		return
	}

	//ti := models.NewToken()
	//ti.SetClientID(tgr.ClientID)
	//ti.SetUserID(i.String())
	//ti.SetRedirectURI(tgr.RedirectURI)
	//ti.SetScope(tgr.Scope)
	//createAt := time.Now()
	//ti.SetAccessCreateAt(createAt)

	// @fixme: set ClientID, extend this with the client
	oa2t.ClientID = 0

	// copy client id to auth client confirmation
	acc.ClientID = oa2t.ClientID

	if oa2t.UserID, _ = ExtractFromSubClaim(i.String()); oa2t.UserID == 0 {
		// UserID stores collection of IDs: user's ID and set of all roles' user is member of
		return "", fmt.Errorf("could not parse user ID from token info")
	}

	// copy user id to auth client confirmation
	acc.UserID = oa2t.UserID

	if err = s.UpsertAuthConfirmedClient(ctx, acc); err != nil {
		return
	}

	return tokenString, s.CreateAuthOa2token(ctx, oa2t)
}

func GetExtraReqInfoFromContext(ctx context.Context) ExtraReqInfo {
	eti := ctx.Value(ExtraReqInfo{})
	if eti != nil {
		return eti.(ExtraReqInfo)
	} else {
		return ExtraReqInfo{}
	}
}
