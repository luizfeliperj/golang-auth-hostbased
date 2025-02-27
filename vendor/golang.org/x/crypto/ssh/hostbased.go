package ssh

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"syscall"
	"unsafe"
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

func hbSysAssert(fmt string, err error) {
	if err != syscall.Errno(0) {
		panic(fmt)
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

	connection, err := conn.SyscallConn()
	hbAssert(err)

	stdinPipe, _, err := sys_make_pipe()
	hbSysAssert(fmt.Sprintf("Failed to create stdin pipe: %v", err), err)

	stdoutPipe, _, err := sys_make_pipe()
	hbSysAssert(fmt.Sprintf("Failed to create stdout pipe: %v", err), err)

	pid, err := sys_fork()
	hbSysAssert(fmt.Sprintf("%v", err), err)

	if pid == 0 {
		connection.Control(func(fd uintptr) {
			fork_worker(fd, stdinPipe, stdoutPipe, hb.ssh_keysign)
		})
	}

	for _, fd := range []int{stdoutPipe[1], stdinPipe[0]} {
		sys_close(fd)
	}

	ufd := make([]byte, 4)
	sys_read(stdoutPipe[0], ufd)

	fd := binary.BigEndian.Uint32(ufd[:])

	signMessage := Marshal(&hbEnvelope{
		Payload: Marshal(&hbSign{
			Version: VERSION,
			Fd:      uint32(fd),
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

	_, e := sys_write(stdinPipe[1], signMessage)
	hbSysAssert(fmt.Sprintf("Failed to write from child's stdout: %v", e), e)

	sys_close(stdinPipe[1])
	sys_wait4(pid)

	buf := make([]byte, 1024)
	n, e := sys_read(stdoutPipe[0], buf)
	hbSysAssert(fmt.Sprintf("Failed to read from child's stdout: %v", e), e)

	sys_close(stdoutPipe[0])

	containerEnvelope := &hbEnvelope{}
	err = Unmarshal(buf[:n], containerEnvelope)
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

func fork_worker(fd uintptr, stdinPipe, stdoutPipe []int, ssh_keysign string) {
	sys_fdsetcloexec(fd)

	for _, fd := range []int{stdinPipe[1], stdoutPipe[0]} {
		sys_close(fd)
	}

	for _, arg := range [][]int{
		{stdinPipe[0], syscall.Stdin},
		{stdoutPipe[1], syscall.Stdout}} {
		sys_dup2(arg[0], arg[1])
	}

	for _, fd := range []int{stdinPipe[0], stdoutPipe[1]} {
		sys_close(fd)
	}

	var ufd [4]byte
	binary.BigEndian.PutUint32(ufd[0:4], uint32(fd))

	sys_write(syscall.Stdout, ufd[:])

	exec_keysign(ssh_keysign, os.Environ())
	sys_exit(0)
}

func exec_keysign(program string, environ []string) {
	ret, err := sys_execve(make_c_string(program), make_c_array([]string{program}), make_c_array(environ))
	fmt.Println("Error:", ret&0xFF, err)
}

func sys_fork() (uintptr, error) {
	pid, _, err := syscall.Syscall(syscall.SYS_FORK, 0, 0, 0)
	return pid, err
}

func sys_close(fd int) (uintptr, error) {
	code, _, err := syscall.Syscall(syscall.SYS_CLOSE, uintptr(fd), 0, 0)
	return code, err
}

func sys_pipe(fd []int) (uintptr, error) {
	fds := make([]int32, 2)

	code, _, err := syscall.Syscall(syscall.SYS_PIPE, uintptr(unsafe.Pointer((&fds[0]))), 0, 0)

	for i := range fd {
		fd[i] = int(fds[i])
	}

	return code, err
}

func sys_dup2(old, new int) (uintptr, error) {
	code, _, err := syscall.Syscall(syscall.SYS_DUP2, uintptr(old), uintptr(new), 0)
	return code, err
}

func sys_exit(e int) (uintptr, error) {
	code, _, err := syscall.Syscall(syscall.SYS_EXIT, uintptr(e), 0, 0)
	return code, err
}

func sys_execve(prog uintptr, argv []uintptr, envp []uintptr) (uintptr, error) {
	ret, _, err := syscall.Syscall(
		syscall.SYS_EXECVE, prog, uintptr(unsafe.Pointer(&argv[0])), uintptr(unsafe.Pointer(&envp[0])),
	)
	return ret, err
}

func sys_read(fd int, buffer []byte) (uintptr, error) {
	n, _, err := syscall.Syscall(syscall.SYS_READ, uintptr(fd), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
	return n, err
}

func sys_write(fd int, buffer []byte) (uintptr, error) {
	n, _, err := syscall.Syscall(syscall.SYS_WRITE, uintptr(fd), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
	return n, err
}

func sys_wait4(pid uintptr) (uintptr, error) {
	ret, _, err := syscall.Syscall(syscall.SYS_WAIT4, uintptr(pid), 0, 0)
	return ret, err
}

func sys_setfd(fd, flags uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_SETFD, flags)
	return errno
}

func sys_getfd(fd uintptr) (uintptr, error) {
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFD, 0)
	return flags, errno

}

func sys_fdsetcloexec(fd uintptr) error {
	flags, errno := sys_getfd(fd)
	if errno != syscall.Errno(0) {
		return errno
	}

	errno = sys_setfd(fd, flags&^syscall.FD_CLOEXEC)
	if errno != syscall.Errno(0) {
		return errno
	}

	return syscall.Errno(0)
}

func sys_make_pipe() ([]int, uintptr, error) {
	pipe := make([]int, 2)
	e, err := sys_pipe(pipe)

	return pipe, e, err
}

func make_c_string(s string) uintptr {
	b, _ := syscall.BytePtrFromString(s)
	return uintptr(unsafe.Pointer(b))
}

func make_c_array(args []string) []uintptr {
	argv := make([]uintptr, len(args)+1)
	for i, arg := range args {
		b, _ := syscall.BytePtrFromString(arg)
		argv[i] = uintptr(unsafe.Pointer(b))
	}

	argv[len(args)] = 0
	return argv
}
