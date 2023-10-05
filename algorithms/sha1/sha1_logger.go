package sha1

import "fmt"

type logger struct{}

func (l *logger) logW(i int, w uint32) {
	fmt.Printf("w[%d] = %d \n", i, w)
}
