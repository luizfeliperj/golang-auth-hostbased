# ssh host based authentication for Golang's golang.org/x/crypto/ssh

This is a patch to add a new ssh.AuthMethod called ssh.HostBased in order to provide host based authentication for golang's ssh client as provided by golang.org/x/crypto/ssh package.

This patch implements [RFC 4252 Section 9][rfc] authenticatation with the server using the private host key of the client by signing the authentication request using OpenSSH's ssh-keysign, so it does require hostbased autentication up and running using OpenSSH clients.

This repository also provides a sample usage of this patch.

Learn more by visiting golang GitHub issue [68772][issue].

[issue]: <https://github.com/golang/go/issues/68772>
[rfc]: <https://datatracker.ietf.org/doc/html/rfc4252#section-9>
