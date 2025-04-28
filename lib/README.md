# MasQiTT library source code

These files in `lib` are compiled into the MasQiTT library.

## Files

#### Top level files

- `masqitt.c` and `../include/masqitt.h`

    These files provide the interface used by MQTT Clients to incorporate
    Secure MQTT into their processing. Clients written to the Mosquitto API
    need only to change some calls to use those described in `masqitt.h`
    instead. (See the porting guide in [the examples README](../examples).)
    Those routines perform Secure MQTT encryption and decryption in a shim
    layer between the Client code and the Mosquitto API.

    Client code should need to `#include` only `masqitt.h`.  It pulls in the
    other needed `.h` files.

- `../include/masqlib.h`

    This file is `#include`d by the `*.c` files below. It contains the
    essential definitions needed across the MasQiTT code that implements
    Secure MQTT.

#### Files implementing Secure MQTT

- `ibe.c` and `../include/ibe.h`

    These files provide the Identity-Based Encryption routines needed to
    encapsulate and decapsulate (recover) the AES keys used to encrypt
    Secure MQTT Topic Values. This code calls functions in the MIRACL Core
    library.

    There should be no need to call any of these routines directly from
    MasQiTT Client code.

- `crypto.c` and `../include/crypto.h`

    These files implement the cryptographic processing for Secure MQTT using
    the IBE routines above.

    These utility routines may come in handy:

    - `MASQ_rand_bytes()`
    - `MASQ_rand_clientid()`
    - `MASQ_hash()` (SHA256)

    There should be no need to call any of the other `MASQ_*()` routines
    from `crypto.c` directly from MasQiTT Client code.

- `kms_msg.c` and `../include/kms_msg.h`

    This file contains the routines to create and parse Key Management
    Server (KMS) packets.

- `api.c` and `../include/api.c`

    This is the top-level API for MasQiTT crypto magic used by
    `masqitt.c`. See `api.h` for documentation.

    Publisher code will generally call:

    - `MASQ_crypto_api_init()`
    - `MASQ_crypto_api_encrypt()`
    - `MASQ_crypto_api_encrypt()`
    - ...
    - `MASQ_crypto_api_close()`

    Subscribers will generally call:

    - `MASQ_crypto_api_init()`
    - `MASQ_crypto_api_decrypt()`
    - `MASQ_crypto_api_decrypt()`
    - ...
    - `MASQ_crypto_api_close()`

    Of particular interest is the `MASQ_user_properties_t` struct
    defined in `masqlib.h`. Calling `MASQ_crypto_api_encrypt()`
    returns data in this struct that should be used to create an MQTT
    PUBLISH packet. Conversely, this struct must be populated with
    data obtained by parsing a received PUBLISH packet and provided to
    `MASQ_crypto_api_decrypt()`.

- `../include/tls.h`

    Just enough `#include` magic to support TLS-protected communications
    between Clients and the KMS.

> If you have `doxygen` installed on your system, you can run `make doc` to
  generate documentation in `doc/html/index.html`

## Use
   
MasQiTT sits on top of Mosquitto's API and uses Mosquitto to handle the
actual passing of MQTT messages. MasQiTT assumes it is being installed on a
system where Mosquitto development is already taking place. If Mosquitto is
not installed on your system (check for the existence of
`/usr/local/lib/libmosquitto.so`), see the User Guide. MasQiTT has been
developed with Mosquitto version 2.0.15, and tested with Mosquitto versions
2.0.15 and 2.0.18.

wolfSSL is used for TLS-protected communication between Clients and the
KMS. On Ubuntu, you can `sudo apt install libwolfssl-dev`

If you prefer to build wolfSSL from source code, obtain it from
[wolfSSL](https://wolfssl.com) and

```bash
$ unzip -l wolfssl-5.7.0.zip
$ cd wolfssl-5.7.0
$ ./configure --enable-harden
$ make
$ sudo make install
```

The IBE crypto routines are built on top of [MIRACL
Core](https://github.com/miracl/core) 4.1. The top-level directory of this
code should be at the same level as the MasQiTT top-level directory.

```bash
$ cd <whatever>/masqitt
$ cd ..
$ git clone https://github.com/miracl/core.git
```

Compile your code against the MasQiTT library by pointing the `-I` compiler
argument at wherever the MasQiTT include files are hiding out
(`/usr/include/masqitt` after you `sudo make install`). If you write code
with `#include` files specified as

```C
#include <masqitt/masqitt.h>
```

you shouldn't need a `-I` on your compile line.

#### Troubleshooting

The current `Makefile` builds `libmasqitt.so` as a shared library. If
your program can't find it, set `$LD_LIBRARY_PATH` to include its directory.
(`$LD_LIBRARY_PATH` works like `$PATH`, but for shared libraries.)

```bash
$ LD_LIBRARY_PATH="/usr/local/lib:${LD_LIBRARY_PATH}" export LD_LIBRARY_PATH
```

### Debugging

For more complete information on testing, see [the tests README](../tests).

```bash
$ cd ..
$ make test
$ cd tests
$ ./msgtest
$ ./kmstest
$ ./cryptotest
$ ./apitest
$ ./clienttest
```

`make test` builds `libmasqittdb.so` with the same functionality as
`libmasqitt.so` but with tons of debugging output enabled. This may be helpful
when debugging your code or it may be simply overwhelming. *Caveat auctor.*

### Clean up

```bash
$ make clean
```

*or*

```bash
$ make realclean
```
