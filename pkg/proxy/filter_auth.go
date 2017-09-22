package proxy

import (
	"errors"
	"github.com/tongv/gateway/pkg/filter"
	"github.com/valyala/fasthttp"
)

var (
	// ErrAuth target
	ErrAuthCheck = errors.New("Err, Auth Error")
)

// AuthFilter AuthFilter
type AuthFilter struct {
	filter.BaseFilter
}

func newAuthFilter() filter.Filter {
	return &AuthFilter{}
}

// Name return name of this filter
func (f AuthFilter) Name() string {
	return FilterHeader
}

// Pre execute before proxy
func (f AuthFilter) Pre(c filter.Context) (statusCode int, err error) {
	if !c.AuthCheck() {
		return fasthttp.StatusForbidden, ErrAuthCheck
	}
	return f.BaseFilter.Pre(c)
}