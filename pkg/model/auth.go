package model

import (
	"fmt"

	"github.com/valyala/fasthttp"
)
func authCheckDispatch(ctx *fasthttp.RequestCtx) bool{
	switch string(ctx.Request.Header.Peek("auth-type")){
		case "1","json":
			return authCheckJson(ctx)
		case "2","secret":
			return authCheckSecret(ctx)
		case "3","file":
			return authCheckFile(ctx)
	}
	return false
}
func authCheckSecret(ctx *fasthttp.RequestCtx) bool{
	fmt.Println("======se====")
	return true
}
func authCheckFile(ctx *fasthttp.RequestCtx) bool{
	fmt.Println("======mu====")
	return true
}
func authCheckJson(ctx *fasthttp.RequestCtx) bool{
	fmt.Println("======js====")
	return true
}
