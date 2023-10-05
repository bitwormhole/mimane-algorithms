package sha1

import (
	"strconv"

	"github.com/bitwormhole/mimane-algorithms/analysis/microscope"
)

type probe struct {
	context *microscope.Context
	digest  *digest

	data microscope.BinaryProbe
	h    [5]microscope.Uint32Probe
	x    [chunk]microscope.ByteProbe
	nx   microscope.IntProbe
	len  microscope.Uint64Probe
}

func (p *probe) init() {

	ctx := p.context
	factory := ctx.ProbeFactory

	for i := range p.h {
		index := strconv.Itoa(i)
		p.h[i] = factory.NewUint32Probe(ctx, "h_"+index)
	}

	for i := range p.x {
		index := strconv.Itoa(i)
		p.x[i] = factory.NewByteProbe(ctx, "x_"+index)
	}

	p.len = factory.NewUint64Probe(ctx, "len")
	p.nx = factory.NewIntProbe(ctx, "nx")
}

func (p *probe) capture() {

	d := p.digest

	for i, value := range d.h {
		p.h[i].Write(value)
	}

	for i, value := range d.x {
		p.x[i].Write(value)
	}

	p.len.Write(d.len)
	p.nx.Write(d.nx)
}
