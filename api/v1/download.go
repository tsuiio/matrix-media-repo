package v1

import (
	"bytes"
	"net/http"

	"github.com/t2bot/matrix-media-repo/api/_apimeta"
	"github.com/t2bot/matrix-media-repo/api/_responses"
	"github.com/t2bot/matrix-media-repo/api/_routers"
	"github.com/t2bot/matrix-media-repo/api/r0"
	"github.com/t2bot/matrix-media-repo/common/rcontext"
	"github.com/t2bot/matrix-media-repo/util/readers"
)

func ClientDownloadMedia(r *http.Request, rctx rcontext.RequestContext, user _apimeta.UserInfo) interface{} {
	r.URL.Query().Set("allow_remote", "true")
	r.URL.Query().Set("allow_redirect", "true")
	return r0.DownloadMedia(r, rctx, user)
}

func FederationDownloadMedia(r *http.Request, rctx rcontext.RequestContext, server _apimeta.ServerInfo) interface{} {
	query := r.URL.Query()
	query.Set("allow_remote", "false")
	query.Set("allow_redirect", "true") // we override how redirects work in the response
	r.URL.RawQuery = query.Encode()
	r = _routers.ForceSetParam("server", r.Host, r)

	res := r0.DownloadMedia(r, rctx, _apimeta.UserInfo{})
	if dl, ok := res.(*_responses.DownloadResponse); ok {
		return &_responses.DownloadResponse{
			ContentType: "multipart/mixed",
			Filename:    "",
			SizeBytes:   0,
			Data: readers.NewMultipartReader(
				&readers.MultipartPart{ContentType: "application/json", Reader: readers.MakeCloser(bytes.NewReader([]byte("{}")))},
				&readers.MultipartPart{ContentType: dl.ContentType, FileName: dl.Filename, Reader: dl.Data},
			),
			TargetDisposition: "attachment",
		}
	} else if rd, ok := res.(*_responses.RedirectResponse); ok {
		return &_responses.DownloadResponse{
			ContentType: "multipart/mixed",
			Filename:    "",
			SizeBytes:   0,
			Data: readers.NewMultipartReader(
				&readers.MultipartPart{ContentType: "application/json", Reader: readers.MakeCloser(bytes.NewReader([]byte("{}")))},
				&readers.MultipartPart{Location: rd.ToUrl},
			),
			TargetDisposition: "attachment",
		}
	} else {
		return res
	}
}