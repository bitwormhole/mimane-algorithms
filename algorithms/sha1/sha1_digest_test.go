package sha1

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func TestSHA1(t *testing.T) {

	// str100
	strMaker := strings.Builder{}
	for i := 0; i < 100; i++ {
		strMaker.WriteString(strconv.Itoa(i))
	}
	str100 := strMaker.String()

	// map[sum]data
	table := make(map[string]string)

	table["27D5482EEBD075DE44389774FCE28C69F45C8A75"] = "h"
	table["A5CEC7AF5F7AAB769CF0D4AA440E01C7BFC371B2"] = "hell"
	table["5EBC311328822A05418FD6F18CE45D60EAABCA25"] = "hello,"
	table["D3F76EB4084CBA78BBFA22FCA02CE522D9B26D31"] = "hello,sha-1"
	table["f0a40ba3b319404dbd729ef32ca29fc897ab8093"] = str100

	// table = make(map[string]string)
	// table["27D5482EEBD075DE44389774FCE28C69F45C8A75"] = "h"

	for k, v := range table {
		data := []byte(v)
		wantSum, err := hex.DecodeString(k)
		if err != nil {
			t.Error(err)
			continue
		}

		// sum := Sum(data)
		sum := SumRemake(data)

		haveSum := sum[:]
		haveSumStr := hex.EncodeToString(haveSum)
		wantSumStr := hex.EncodeToString(wantSum)
		if bytes.Equal(wantSum, haveSum) {
			t.Logf("[OK] sha1sum:%s data:%s\n", haveSumStr, v)
		} else {
			t.Errorf("[Error] sha1sum want:%s have:%s data:%s\n", wantSumStr, haveSumStr, v)
		}
	}
}

func TestSHA1reference(t *testing.T) {
	data := []byte{'h'}
	sum := Sum(data)
	str := hex.EncodeToString(sum[:])
	fmt.Println("sum:" + str)
}

func TestSHA1remake(t *testing.T) {
	data := []byte{'h'}
	sum := SumRemake(data)
	str := hex.EncodeToString(sum)
	fmt.Println("sum:" + str)
}
