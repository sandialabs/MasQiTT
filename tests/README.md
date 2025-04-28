# Crypto test code

## Tests

The files in this directory were written to assist in debugging code in
`../lib`. They are not included in the MasQiTT library.

See the User Guide for a more thorough explanation of these files and how to
run the tests.

- `msgtest.c`

    This file exercises the calls from `kms_msg.c` to check encoding and
    decoding of the packets exchanged with the KMS.

- `kmstest.c`

    `kmstest` *and the tests that follow require a running KMS process to
     talk to.*

    This file tests the communications path with the KMS and proper encoding
    and decoding of KMS packets. It is also useful for working through any
    TLS issues that may arise between a Client and the KMS as it relies on
    no cryptographic processing of packet contents.

- `cryptotest.c`

    This file exercises the calls from `ibe.c` and `crypto.c`.

- `apitest.c`

    This test program exercises the calls from `api.c` (and by extension,
    `ibe.c`, `crypto.c`, and `kms_msg.c`). This may be useful as a worked
    example of how to call the `MASQ_crypto_api_*()` crypto routines.

- `clienttest.c`

    This program exercises KMS communications and proper encryption and
    decryption from the API layer on down.

- `masquitt_test.c`

    This test additionally requires a running (unmodified) Mosquitto Broker
    to talk to.

## Running

To set up these tests with the provided pre-generated test Clients:

```bash
$ cd tests/certs
$ sudo cp -p * /home/kms/ca/
$ su - kms
Password:
kms$ cd ca
kms$ sudo chown kms:kms *
kms$ cd
kms$ cp -p kms-test.cfg kms.cfg
```

Then it is a matter of setting up two terminal windows, one for running the
KMS and the other for running the tests. In the KMS window:

```bash
$ su - kms
kms$ kms -v
```

and in the test window:

```bash
$ cd tests
$ ./msgtest
$ ./kmstest
$ ./cryptotest
$ ./apitest
$ ./clienttest
```

Running `masqitt_test` is left as an exercise for the reader. It requires a
running Mosquitto Broker.

You may need to set/update `$LD_LIBRARY_PATH` in both windows before running
the KMS or tests.

```bash
$ LD_LIBRARY_PATH="/usr/local/lib:${LD_LIBRARY_PATH}" export LD_LIBRARY_PATH
```
