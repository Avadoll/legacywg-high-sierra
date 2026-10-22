package recoverycore

import (
	"encoding/binary"
	"testing"
)

func TestPFInterfaceProjection(t *testing.T) {
	entry := func(name string, flags, states, rules uint32) []byte {
		data := make([]byte, 168)
		copy(data, name)
		binary.LittleEndian.PutUint32(data[152:], flags)
		binary.LittleEndian.PutUint32(data[156:], states)
		binary.LittleEndian.PutUint32(data[160:], rules)
		return data
	}
	valid := append(entry("ALL", 0, 0, 1), entry("utun12", 0x100, 7, 3)...)
	observed, err := decodePFInterfaces(valid)
	if err != nil || len(observed) != 2 || observed[1] != (pfInterfaceObservation{"utun12", 0x100, 7, 3}) {
		t.Fatal("primary interface flags/count projection differs")
	}
	badName := entry("utun12", 0, 0, 1)
	badName[10] = 'x'
	for _, data := range [][]byte{nil, valid[:len(valid)-1], make([]byte, 168*257),
		entry("", 0, 0, 1), entry("abcdefghijklmnop", 0, 0, 1), entry("bad name", 0, 0, 1),
		badName, entry("utun12", 0, 0xffffffff, 1), entry("utun12", 0, 0, 0), entry("utun12", 0, 0, 0xffffffff),
		append(entry("utun12", 0, 0, 1), entry("utun12", 0, 0, 1)...)} {
		if _, err := decodePFInterfaces(data); err == nil {
			t.Fatal("ambiguous or unbounded interface projection accepted")
		}
	}
}
