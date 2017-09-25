package model

import (
	"fmt"
	"testing"
	"github.com/tongv/gateway/pkg/util"
)

func TestEncrypt(t *testing.T) {
	fmt.Println("---------")
	fmt.Println(util.EncryptECB("{'a':1,'bb':2,'c':'xx'}","792ee70e0077c00c0548e58ac36955e9"))
}
func TestDecrypt(t *testing.T) {
	fmt.Println("---------")
	fmt.Println(util.DecryptECB("r5IKNiKJqZ4Iv79T8YkIKOAwe4jnwfknCorP1tWM6B8=","792ee70e0077c00c0548e58ac36955e9"))
}

