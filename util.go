package tentacle

import "net"

func deleteSlice(source []net.Addr, item net.Addr) []net.Addr {
	j := 0
	for _, val := range source {
		if val != item {
			source[j] = val
			j++
		}
	}
	return source[:j]
}

func protectRun(entry func(), report func()) {
	defer func() {
		err := recover()
		if err != nil {
			if report != nil {
				report()
			}
		}
	}()
	entry()
}
