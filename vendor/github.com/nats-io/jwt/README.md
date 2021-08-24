# JWT
A [JWT](https://jwt.io/) implementation that uses [nkeys](https://github.com/itsabgr/nats-server) to digitally sign JWT tokens. 
Nkeys use [Ed25519](https://ed25519.cr.yp.to/) to provide authentication of JWT claims.


[![License Apache 2](https://img.shields.io/badge/License-Apache2-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![ReportCard](http://goreportcard.com/badge/itsabgr/nats-server)](http://goreportcard.com/report/itsabgr/nats-server)
[![Build Status](https://travis-ci.org/itsabgr/nats-server.svg?branch=master)](http://travis-ci.org/itsabgr/nats-server)
[![GoDoc](http://godoc.org/github.com/itsabgr/nats-server?status.png)](http://godoc.org/github.com/itsabgr/nats-server)
[![Coverage Status](https://coveralls.io/repos/github/itsabgr/nats-server/badge.svg?branch=master&t=NmEFup)](https://coveralls.io/github/itsabgr/nats-server?branch=master)

```go
// Need a private key to sign the claim, nkeys makes it easy to create
kp, err := nkeys.CreateAccount()
if err != nil {
    t.Fatal("unable to create account key", err)
}

pk, err := kp.PublicKey()
if err != nil {
	t.Fatal("error getting public key", err)
}

// create a new claim
claims := NewAccountClaims(pk)
claims.Expires = time.Now().Add(time.Duration(time.Hour)).Unix()


// add details by modifying claims.Account

// serialize the claim to a JWT token
token, err := claims.Encode(kp)
if err != nil {
    t.Fatal("error encoding token", err)
}

// on the receiving side, decode the token
c, err := DecodeAccountClaims(token)
if err != nil {
    t.Fatal(err)
}

// if the token was decoded, it means that it
// validated and it wasn't tampered. the remaining and
// required test is to insure the issuer is trusted
pk, err := kp.PublicKey()
if err != nil {
    t.Fatalf("unable to read public key: %v", err)
}

if c.Issuer != pk {
    t.Fatalf("the public key is not trusted")
}
```