# r509-ca-http

r509-ca-http is an HTTP server that runs a certificate authority, for
signing SSL certificates. It is intended to be part of a complete
certificate authority for use in production environments.

## Requirements/Installation

```
$ sudo gem install rspec
$ sudo gem install yard
$ sudo gem install thin
$ sudo gem install rack
$ sudo gem install sinatra
$ sudo gem install dependo
```

You have also to install the r509 library customized

## Configuration

For your CA, you have to generate the certificate `root.cer` and the
private key `root.key`:

```
$ r509.rb --out root.cer --keyout root.key
CSR Bit Length (2048):
Message Digest (SHA1): SHA256
C (US): IT
ST (null by default):
L (null by default):
O (r509 LLC): CA ORGANIZATION.
OU (null by default): A
CN: Private CA
SAN Domains (comma separated):
Self-signed cert duration in days (null disables self-sign): 3650
/C=IT/ST=Turin/L=Turin/O=MyCompany.
/OU=Private Environment/CN=Private Company
```

You have to initialize the revocation list support regardless you won't
use it:

```
$ touch crlnumber.txt list.txt
```

## certificate\_authorities (config.yaml)

You use the `config.yaml` file to specify information about your
certificate authority. You have to configure `tilab` CA that can
have multiple profiles, with one instance of r509-ca-http.

Information about how to construct the YAML can be found at [the
official r509 documentation](https://github.com/r509/r509).

```
$ ca-config.rb --cert root.cer --key root.key --config config.yaml
```

## Middleware (config.ru)

The `config.ru` file configures sinatra and we can run the application locally
using the rackup command.

## Signals

You can send a kill -USR2 signal to any running r509-ca-http process to
cause it to reload and print its config to the logs (provided your app
server isn't trapping USR2 first).

## Rake tasks

There are a few things you can do with Rake:

```
rake gem:build
```

Build a gem file.

```
rake gem:install
```

Install the gem you just built.

```
rake gem:uninstall
```

Uninstall r509-ca-http.

## Run

```
$ sudo rackup -p 9292
```

## API

### Get the CA certificate

```
$ curl -X GET http://127.0.0.1:9292/1/ca/cert
```

The response is the certificate (in PEM format).

### Get the profiles

```
$ curl -X GET http://127.0.0.1:9292/1/ca/profiles
```

The response is the profile list in JSON format:

```
{ "items" : [ "client", "server", "email" ] }
```

### Generate a key pair

```
$ curl -X POST \
> -d type=RSA \
> -d bit_length=2048 \
> http://127.0.0.1:9292/1/keypair
```

The key `type` parameter can be:

- `RSA` (default)
- `DSA`
- `EC`

The `bit_length` parameter is the size of the key (number of bit) for
RSA or DSA key (default 2048).

The `curve_name` parameter is the name of the curve for EC key (default
`secp384r1`).

The response is a JSON object with the following fields:

- `privatekey`: The private key (in PEM format).
- `publickey`: The public key (in PEM format).

### Generate a certificate signing request (CSR)

```
$ curl -X POST \
> -d subject[C]=IT \
> -d subject[ST]=Turin \
> -d subject[L]=Turin \
> -d subject[O]=Private Company S.p.A \
> -d subject[OU]=My Laboratory inside my company building
> -d subject[CN]=frances-co
> -d subject[emailAddress]=frances-co@mmail.it \
> --data-urlencode public_key@publickey.pem \
> http://127.0.0.1:9292/1/certificate/request
```

The `subject` parameters map the subject properties.

The response is the CSR (in PEM format).

### Sign a CSR

```
$ curl -X POST \
> --data-urlencode csr@csr.pem \
> --data-urlencode key@privatekey.pem \
> http://127.0.0.1:9292/1/certificate/request/sign
```

The `csr` parameter is the CSR to sign (in PEM format).

The `key` parameter is the private key of the subject (in PEM format).

The response is the signed CSR (in PEM format).



### Generate a signed CSR

```
$ curl -X POST \
> -d subject[C]=IT \
> -d subject[ST]=Turin \
> -d subject[L]=Turin \
> -d subject[O]=Private Company S.p.A \
> -d subject[OU]=My Lab inside my company building \
> -d subject[CN]=frances-co
> -d subject[emailAddress]=frances.co@mmail.it \
> --data-urlencode key@privatekey.pem \
> http://127.0.0.1:9292/1/certificate/signedrequest
```

The `key` parameter is the private key of the subject (in PEM format).

The other parameters match the parameters of the request
`/1/certificate/request`.

The response is the signed CSR (in PEM format).

### Generate a key pair and a signed CSR

```
$ curl -X POST \
> -d subject[C]=IT \
> -d subject[ST]=Turin \
> -d subject[L]=Turin \
> -d subject[O]=Private Company S.p.A \
> -d subject[OU]=My Lab inside my company building
> -d subject[CN]=frances-co
> -d subject[emailAddress]=frances.co@mmail.it \
> -d newkey[type]=RSA \
> -d newkey[bit_length]=2048 \
> http://127.0.0.1:9292/1/certificate/signedrequest
```

The `newkey` parameters define the parameters for the key pair
generation; the keys of the `newkey` hash match the parameters of the
request `/1/keypair`.

The other parameters match the parameters of the request
`/1/certificate/request`.

The response is a JSON object with the following fields:

- `csr`: The signed CSR (in PEM format).
- `privatekey`: The private key (in PEM format).
- `publickey`: The public key (in PEM format).

### Issue a certificate

```
$ curl -X POST \
> -d profile=server \
> --data-urlencoded csr@csr.pem \
> -d validityPeriod=31536000 \
> http://127.0.0.1:9292/1/certificate/issue
```

The `profile` parameter is the profile for the certificate issuing.

The `csr` parameter is the signed CSR (in PEM format).

The `validityPeriod` parameter is the validity period of the issued
certificate (in seconds).

The response is the certificate (in PEM format).

### Generate a signed CSR and issue a certificate

```
$ curl -X POST \
> -d profile=server \
> -d subject[C]=IT \
> -d subject[ST]=Turin \
> -d subject[L]=Turin \
> -d subject[O]=Private Company%20S.p.A \
> -d subject[OU]=My Lab inside the company building \
> -d subject[CN]=frances-co
> -d subject[emailAddress]=frances-co@mmail.it \
> --data-urlencode key@privatekey.pem \
> -d validityPeriod=31536000 \
> http://127.0.0.1:9292/1/certificate/issue
```

The `profile` parameter is the profile for the certificate issuing.

The `subject` parameters map the subject properties.

The `key` parameter is the private key of the subject (in PEM format).

The `validityPeriod` parameter is the validity period of the issued
certificate (in seconds).

The response is the certificate (in PEM format).

### Generate a key pair and issue a certificate

```
$ curl -X POST \
> -d profile=server \
> -d subject[C]=IT \
> -d subject[ST]=Turin \
> -d subject[L]=Turin \
> -d subject[O]=Private Company S.p.A \
> -d subject[OU]=My Lab inside the company building \
> -d subject[CN]=frances-co
> -d subject[emailAddress]=frances-co@mmail.it \
> -d newkey[type]=RSA \
> -d newkey[bit_length]=2048 \
> -d validityPeriod=31536000 \
> http://127.0.0.1:9292/1/certificate/issue
```

The `newkey` parameters define the parameters for the key pair
generation; the keys of the `newkey` hash match the parameters of the
request `/1/keypair`.

The other parameters match the parameters of the request
`/1/certificate/issue`.

The response is a JSON object with the following fields:

- `cert`: The certificate (in PEM format).
- `privatekey`: The private key (in PEM format).
- `publickey`: The public key (in PEM format).
