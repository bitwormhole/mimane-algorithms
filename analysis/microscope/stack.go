package microscope

import "io"

// KeyPoint 表示调用过程的一个关键点
type KeyPoint struct {
	Class   string
	Name    string
	Message string
}

// Stack 表示一个调用过程的堆栈
type Stack interface {
	Open(kp ...*KeyPoint) io.Closer
	Point(kp *KeyPoint)
}

////////////////////////////////////////////////////////////////////////////////

// NewMockStack 新建一个假冒的 stack
func NewMockStack() Stack {
	return &mockStack{}
}

type mockStack struct {
}

func (inst *mockStack) Open(kp ...*KeyPoint) io.Closer {
	return inst
}

func (inst *mockStack) Point(kp *KeyPoint) {

}

func (inst *mockStack) Close() error {
	return nil
}

////////////////////////////////////////////////////////////////////////////////
