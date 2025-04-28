# Certification Authority

The MasQiTT CA uses OpenSSL to generate keys and certificates. If you do not
have the `openssl` command on your system,

```bash
$ sudo apt install openssl
```

After completing KMS installation, generate the self-signed signing
certificate (`ca-crt.pem`) and the key/certificate for the KMS
(`kms-key.pem` and `kms-crt.pem`) by

```bash
$ su - kms
Password:
kms$ generate_ca
kms$ exit
$
```

This needs to (should only) be done once at system provisioning time.

You will need to create a public/private key pair (private key file and
certificate file) for a Client before you can enroll it. Conveniently,
generating a key pair also enrolls a Client. After enrollment, the Client's
private key file, certificate, and a copy of the top-level signing
certificate (`ca-crt.pem`) go to the Client.

Enroll a Client so the KMS recognizes it and can communicate with it by

```bash
$ su - kms
Password:
kms$ generate_client_cert ClientID role
kms$ exit
$
```

`ClientID` above is the 16-character Secure MQTT Client ID. `role` is one of
`pub` (for a Publisher), `sub` (Subscriber), or `both` (for a Client that
both subscribes and publishes).  `generate_client_cert` will create two
files: *ClientID*`-key.pem` (private key) and *ClientID*`-crt.pem`
(certificate) in `~kms/ca`.

Among other things, the enrollment process adds a Client to the KMS's
`kms.cfg` configuration file. As intitally configured, the KMS will refuse
to communicate with a Client that does not appear in `kms.cfg`.

`rand_id` generates a random 16-character Client ID, which may be useful at
enrollment time. The likelihood of it generating an ID that already exists
in the config file is quite small, but it's up to you to check for
potiential duplicates. Worst case, `generate_client_cert` will refuse to
enroll a Client if its ID is found in `kms.cfg`.
