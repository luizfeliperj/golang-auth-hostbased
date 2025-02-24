package ssh

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
)

const (
	VERSION = 2
	MSGTYPE = 50
)

type hostbasedAuth struct {
	ssh_keysign string
	hostkey     *bytes.Buffer
}

type hbEnvelope struct {
	Payload []byte
}

type hbSign struct {
	Version uint8
	Fd      uint32
	Payload []byte
}

type hbSigned struct {
	Version uint8
	Payload []byte
}

type hbSignMessage struct {
	Session   []byte
	Msgtype   uint8
	Sshuser   string
	Service   string
	Method    string
	Hostalgo  string
	Blob      []byte
	Localhost string
	Localuser string
}

type hbSignedMessage struct {
	Msgtype   uint8
	Sshuser   string
	Service   string
	Method    string
	Hostalgo  string
	Blob      []byte
	Localhost string
	Localuser string
	Signature []byte
}

func hbAssert(err error) {
	if err != nil {
		panic(err)
	}
}

func (hb *hostbasedAuth) auth(session []byte, sshuser string, c packetConn, rand io.Reader, _ map[string][]byte) (result authResult, authmethods []string, returnerror error) {
	defer func() {
		if r := recover(); r != nil {
			none := new(noneAuth)
			_, authmethods, _ = none.auth(session, sshuser, c, rand, nil)
			result = authFailure
			returnerror = fmt.Errorf("%s", r)
		}
	}()

	ht := c.(*handshakeTransport)
	transport := (*ht).conn.(*transport)
	conn := transport.Closer.(*net.TCPConn)

	localaddr := conn.LocalAddr().String()

	localhost, _, err := net.SplitHostPort(localaddr)
	hbAssert(err)

	localname, err := net.LookupAddr(localhost)
	hbAssert(err)

	localuser, err := user.Current()
	hbAssert(err)

	stdout := &bytes.Buffer{}

	signMessage := Marshal(&hbEnvelope{
		Payload: Marshal(&hbSign{
			Version: VERSION,
			Fd:      uint32(3),
			Payload: Marshal(&hbSignMessage{
				Session:   session,
				Msgtype:   MSGTYPE,
				Sshuser:   sshuser,
				Service:   serviceSSH,
				Method:    hb.method(),
				Hostalgo:  ht.algorithms.hostKey,
				Blob:      hb.hostkey.Bytes(),
				Localhost: localname[0],
				Localuser: localuser.Username,
			}),
		}),
	})

	connection, err := conn.SyscallConn()
	hbAssert(err)

	connection.Control(func(fd uintptr) {
		cmd := exec.Command(hb.ssh_keysign)

		cmd.ExtraFiles = []*os.File{
			os.NewFile(fd, "connection"),
		}

		cmd.Stdout = stdout

		stderr := &bytes.Buffer{}
		cmd.Stderr = stderr

		cmd.Stdin = bytes.NewBuffer(signMessage)

		err = cmd.Start()
		hbAssert(err)

		err = cmd.Wait()
		if err != nil {
			if stderr.Len() > 0 {
				panic(stderr.String())
			}
			panic(err)
		}
	})

	containerEnvelope := &hbEnvelope{}
	err = Unmarshal(stdout.Bytes(), containerEnvelope)
	hbAssert(err)

	signed := &hbSigned{}
	err = Unmarshal(containerEnvelope.Payload, signed)
	hbAssert(err)

	if signed.Version != VERSION {
		panic("signed version mismatch")
	}

	signedMessage := Marshal(&hbSignedMessage{
		Blob:      hb.hostkey.Bytes(),
		Msgtype:   MSGTYPE,
		Method:    hb.method(),
		Sshuser:   sshuser,
		Service:   serviceSSH,
		Hostalgo:  ht.algorithms.hostKey,
		Localhost: localname[0],
		Localuser: localuser.Username,
		Signature: signed.Payload,
	})

	err = c.writePacket(signedMessage)
	if err != nil {
		return authFailure, nil, err
	}

	return handleAuthResponse(c)
}

func (hb *hostbasedAuth) method() string {
	return "hostbased"
}

func Hostbased(hostkey *bytes.Buffer, ssh_keysign string) AuthMethod {
	method := &hostbasedAuth{
		hostkey:     hostkey,
		ssh_keysign: ssh_keysign,
	}

	return method
}
