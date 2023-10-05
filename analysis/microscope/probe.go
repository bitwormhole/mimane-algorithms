package microscope

type Probe interface {
	Name() string
}

type ProbeFactory interface {
	NewByteProbe(c *Context, name string) ByteProbe

	NewRuneProbe(c *Context, name string) RuneProbe

	NewStringProbe(c *Context, name string) StringProbe

	NewBinaryProbe(c *Context, name string) BinaryProbe

	NewIntProbe(c *Context, name string) IntProbe

	NewUint32Probe(c *Context, name string) Uint32Probe

	NewUint64Probe(c *Context, name string) Uint64Probe
}

////////////////////////////////////////////////////////////////////////////////

type ByteProbe interface {
	Probe
	Write(value byte)
	Value() byte
}

type BinaryProbe interface {
	Probe
	Write(value []byte)
	Value() []byte
}

type BooleanProbe interface {
	Probe
	Write(value bool)
	Value() bool
}

type RuneProbe interface {
	Probe
	Write(value rune)
	Value() rune
}

type StringProbe interface {
	Probe
	Write(value string)
	Value() string
}

type IntProbe interface {
	Probe
	Write(value int)
	Value() int
}

type Uint32Probe interface {
	Probe
	Write(value uint32)
	Value() uint32
}

type Uint64Probe interface {
	Probe
	Write(value uint64)
	Value() uint64
}
