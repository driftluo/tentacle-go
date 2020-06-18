package tentacle

import (
	"errors"
	"net"
	"testing"
)

func TestSelectVersion(t *testing.T) {
	a := []string{
		"1.0.0",
		"1.1.1",
		"2.0.0",
	}
	b := []string{
		"1.0.0",
		"2.0.0",
		"3.0.0",
	}
	c := []string{}
	d := []string{"5.0.0"}
	e := []string{"1.0.0"}

	var res string
	var err error
	res, err = SelectVersion(b, a)
	if res != "2.0.0" {
		t.Fatal("b, a != 2.0.0")
	}

	res, err = SelectVersion(b, e)
	if res != "1.0.0" {
		t.Fatal("b, e != 1.0.0")
	}

	res, err = SelectVersion(b, c)
	if err == nil {
		t.Fatal("b, c != nil")
	}
	res, err = SelectVersion(b, d)
	if err == nil {
		t.Fatal("b, d != nil")
	}
	res, err = SelectVersion(d, a)
	if err == nil {
		t.Fatal("d, a != nil")
	}
	res, err = SelectVersion(d, e)
	if err == nil {
		t.Fatal("d, e != nil")
	}
	res, err = SelectVersion(e, d)
	if err == nil {
		t.Fatal("e, d != nil")
	}
}

func TestProtocolInfoDecodeEncode(t *testing.T) {
	info := new(ProtocolInfo)
	info.name = "test"
	info.supportVersion = []string{"1.0.0", "2.0.0"}

	b := info.encode()

	decode, err := decodeToProtocolInfo(b)
	if err != nil {
		t.Fatal(err)
	}

	if info.name != decode.name {
		t.Fatal("name must eq")
	}

	if len(info.supportVersion) != len(decode.supportVersion) {
		t.Fatal("supportVersion len must eq")
	}

	for i, v := range info.supportVersion {
		if decode.supportVersion[i] != v {
			t.Fatal("supportVersion must eq")
		}
	}
}

func selectProtocol(server, client []string, result string) error {
	serverInfo := new(ProtocolInfo)
	serverInfo.name = "test"
	serverInfo.supportVersion = server

	infoI := info{inner: *serverInfo, fn: SelectVersion}

	serverInfos := map[string]info{"test": infoI}

	clientInfo := new(ProtocolInfo)
	clientInfo.name = "test"
	clientInfo.supportVersion = client

	resChan := make(chan string)
	addrChan := make(chan net.Addr)

	go func() {
		listener, _ := net.Listen("tcp", ":0")
		addrChan <- listener.Addr()
		defer listener.Close()
		conn, _ := listener.Accept()

		_, res, _ := serverSelect(conn, serverInfos)
		resChan <- res
	}()

	addr := <-addrChan
	conn, _ := net.Dial("tcp", addr.String())
	_, res, _ := clientSelect(conn, *clientInfo)

	serverRet := <-resChan

	if res != serverRet {
		return errors.New("client server don't match")
	}

	if res != result {
		return errors.New("result don't match")
	}
	return nil
}

func TestSelectSame(t *testing.T) {
	err := selectProtocol([]string{"1.0.0", "1.1.1"}, []string{"1.0.0", "1.1.1"}, "1.1.1")

	if err != nil {
		t.Fatal(err)
	}
}

func TestSelectDiff(t *testing.T) {
	err := selectProtocol([]string{"1.0.0", "2.1.1"}, []string{"1.0.0", "1.1.1"}, "1.0.0")

	if err != nil {
		t.Fatal(err)
	}
}

func TestSelectFail(t *testing.T) {
	err := selectProtocol([]string{"1.0.0", "1.1.1"}, []string{"2.0.0", "2.1.1"}, "")

	if err != nil {
		t.Fatal(err)
	}
}
