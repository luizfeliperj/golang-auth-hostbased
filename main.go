package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
)

const (
	ssh_keysign = "/usr/libexec/openssh/ssh-keysign"
)

func main() {
	if len(os.Args) != 4 {
		log.Fatalf("Usage: %s <user> <host:port> <command>", os.Args[0])
	}

	client, session, err := connectToHost(os.Args[1], os.Args[2])
	if err != nil {
		panic(err)
	}
	out, err := session.CombinedOutput(os.Args[3])
	if err != nil {
		panic(err)
	}

	fmt.Println(string(out))
	client.Close()
}

func connectToHost(user, host string) (*ssh.Client, *ssh.Session, error) {

	hostkey := &bytes.Buffer{}
	client, err := ssh.Dial("tcp", host, &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Hostbased(
				hostkey,
				ssh_keysign,
			),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			hostkey.Write(key.Marshal())
			return nil
		},
	})
	if err != nil {
		return nil, nil, err
	}

	session, err := client.NewSession()
	if err != nil {
		client.Close()
		return nil, nil, err
	}

	return client, session, nil
}
