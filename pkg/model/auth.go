package model

import (
	"fmt"
	"strings"
	"sort"
	"crypto/md5"
	"github.com/tongv/gateway/pkg/util"
	"github.com/valyala/fasthttp"
)
func authCheckDispatch(ctx *fasthttp.RequestCtx,out *fasthttp.Request,aHash AuthHash) bool{
	app := string(ctx.Request.Header.Peek("x-auth-app"))
	timestamp := string(ctx.Request.Header.Peek("x-auth-timestamp"))
	if timestamp == "" || app == ""{
		return false
	}
	appkey,appkeyExists := aHash[app]
	if !appkeyExists{
		fmt.Println("!appkeyExists")
		return false
	}
	
	//get real key use in check
	ckey := signData(appkey+timestamp)

	switch string(ctx.Request.Header.Peek("x-auth-type")){
		case "1","json":
			return authCheckJson(ctx,ckey)
		//this way will replace out request body with realdata!
		case "2","secret":
			return authCheckSecret(ctx,out,ckey)
		case "3","file":
			return authCheckFile(ctx,ckey)
	}
	return false
}
//json api check
func authCheckJson(ctx *fasthttp.RequestCtx,ckey []byte) bool{
	sign := string(ctx.Request.Header.Peek("x-auth-sign"))
	if sign == ""{
		return false
	}
	//SignData(body.(string)+ckey.(string))
	return fmt.Sprintf("%x",signData(string(ctx.PostBody())+fmt.Sprintf("%x",ckey))) == sign
}
//secret api check
func authCheckSecret(ctx *fasthttp.RequestCtx,out *fasthttp.Request,ckey []byte) bool{
	realdata,err := util.DecryptECB(string(ctx.PostBody()),fmt.Sprintf("%x",ckey))
	if err!=nil || realdata==""{
		return false
	}
	out.SetBodyString(realdata)
	return true
}
//file api check
func authCheckFile(ctx *fasthttp.RequestCtx,ckey []byte) bool{
	sign := string(ctx.Request.Header.Peek("x-auth-sign"))
	if sign == ""{
		return false
	}
	
	form,formErr := ctx.MultipartForm()
	if formErr != nil{
		fmt.Println(formErr)
		return false
	}
	
	if len(form.Value) == 0{
		return true
	}
	
	//SignData("k1=v1&k2=v2&k3=v3"+ckey.(string))
	var data []string
	for k,v := range form.Value{
		data = append(data,k+"="+v[0])
	}
//	fmt.Printf("\n\nbefor【%+v】\n\n",data)
    sort.Strings(data)
//	fmt.Printf("\n\nafter【%+v】\n\n",data)
	fmt.Printf("\n\n【%s】\n\n",strings.Join(data,"&")+fmt.Sprintf("%x",ckey))
	return fmt.Sprintf("%x",signData(strings.Join(data,"&")+fmt.Sprintf("%x",ckey))) == sign
}


func signData(str string) []byte{
	hashFac := md5.New()
	hashFac.Write([]byte(str))
	return hashFac.Sum(nil)
}