package sha1

import (
	"bytes"
	"encoding/binary"
	"math/bits"
)

const (
	idxA = 0
	idxB = 1
	idxC = 2
	idxD = 3
	idxE = 4
)

type stepFunc func(abcde []uint32) uint32

type sha1digest struct {

	// out of block
	block [chunk]byte // 64 * 8 = 512 bits
	count uint64      // total length

	// in block
	w     [80]uint32
	abcde [5]uint32 //  [a,b,c,d,e]
}

func (inst *sha1digest) reset() {
	inst.abcde[idxA] = init0
	inst.abcde[idxB] = init1
	inst.abcde[idxC] = init2
	inst.abcde[idxD] = init3
	inst.abcde[idxE] = init4
	inst.count = 0
}

func (inst *sha1digest) write(data []byte) {
	cnt := inst.count
	for _, x := range data {
		inst.block[cnt%chunk] = x
		cnt++
		if (cnt % chunk) == 0 {
			inst.computeBlock()
		}
	}
	inst.count = cnt
}

func (inst *sha1digest) sum() []byte {

	cnt := inst.count
	lenBytes := inst.uint642bytes(cnt << 3)
	h80 := []byte{0x80}
	h00 := []byte{0}
	total := cnt + 1 + 8

	inst.write(h80)
	for yu := total % chunk; 0 < yu && yu < chunk; yu++ {
		inst.write(h00)
	}
	inst.write(lenBytes[:])

	b := bytes.Buffer{}
	for _, x := range inst.abcde {
		b4 := inst.uint2bytes(x)
		b.Write(b4[:])
	}
	return b.Bytes()
}

func (inst *sha1digest) bytes2uint(data [4]byte) uint32 {
	return binary.BigEndian.Uint32(data[:])
}

func (inst *sha1digest) uint2bytes(n uint32) [4]byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], n)
	return b
}

func (inst *sha1digest) uint642bytes(n uint64) [8]byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], n)
	return b
}

func (inst *sha1digest) computeBlock() {

	inst.prepareWx()

	a2e := inst.abcde

	inst.computeStepX20(inst.w[0:20], _K0, a2e[:], inst.stepFunc0)
	inst.computeStepX20(inst.w[20:40], _K1, a2e[:], inst.stepFunc20)
	inst.computeStepX20(inst.w[40:60], _K2, a2e[:], inst.stepFunc40)
	inst.computeStepX20(inst.w[60:80], _K3, a2e[:], inst.stepFunc60)

	for i := range a2e {
		inst.abcde[i] += a2e[i]
	}
}

func (inst *sha1digest) computeStepX20(wlist []uint32, k uint32, abcde []uint32, fn stepFunc) {
	for _, w := range wlist {
		inst.computeStepX1(w, k, abcde, fn)
	}
}

func (inst *sha1digest) computeStepX1(w uint32, k uint32, abcde []uint32, fn stepFunc) {

	a1 := abcde[idxA]
	b1 := abcde[idxB]
	c1 := abcde[idxC]
	d1 := abcde[idxD]
	e1 := abcde[idxE]

	a2 := e1
	b2 := a1
	c2 := bits.RotateLeft32(b1, 30)
	d2 := c1
	e2 := d1

	a2 += fn(abcde)
	a2 += bits.RotateLeft32(a1, 5)
	a2 += w
	a2 += k

	abcde[idxA] = a2
	abcde[idxB] = b2
	abcde[idxC] = c2
	abcde[idxD] = d2
	abcde[idxE] = e2
}

func (inst *sha1digest) stepFunc0(abcde []uint32) uint32 {
	b := abcde[idxB]
	c := abcde[idxC]
	d := abcde[idxD]
	// return (b & c) | ((^b) & d)
	return b&c | (^b)&d
}

func (inst *sha1digest) stepFunc20(abcde []uint32) uint32 {
	b := abcde[idxB]
	c := abcde[idxC]
	d := abcde[idxD]
	return b ^ c ^ d
}

func (inst *sha1digest) stepFunc40(abcde []uint32) uint32 {
	b := abcde[idxB]
	c := abcde[idxC]
	d := abcde[idxD]
	return (b & c) | (c & d) | (d & b)
}

func (inst *sha1digest) stepFunc60(abcde []uint32) uint32 {
	b := abcde[idxB]
	c := abcde[idxC]
	d := abcde[idxD]
	return b ^ c ^ d
}

func (inst *sha1digest) prepareWx() {

	i := 0
	w := inst.w[:]

	// w[0] ~ w[15]
	var b4 [4]byte
	for ; i <= 15; i++ {
		offset := i * 4
		b4[0] = inst.block[offset]
		b4[1] = inst.block[offset+1]
		b4[2] = inst.block[offset+2]
		b4[3] = inst.block[offset+3]
		w[i] = inst.bytes2uint(b4)
	}

	// w[16] ~ w[79]
	for ; i <= 79; i++ {
		n := w[i-16] ^ w[i-14] ^ w[i-8] ^ w[i-3]
		w[i] = bits.RotateLeft32(n, 1)
	}
}

func SumRemake(data []byte) []byte {
	d := sha1digest{}
	d.reset()
	d.write(data)
	return d.sum()
}
