package microscope

type Context struct {
	Probes []Probe

	ProbeFactory ProbeFactory

	Stack Stack
}
