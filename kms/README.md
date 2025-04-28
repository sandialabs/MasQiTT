# KMS source code

## Files

- `cache.c` and `cache.h`

    The routines in this file manage the KMS cache of IBE private keys so
    they can be calculated once, retrieved later as needed, and pruned after
    expiration.

- `cfg.c` and `cfg.h`

    These routines provide an interface to `libconfig` for reading the KMS
    configuration file.

- `kms_main.c`

    This is the Key Management Server executable.

- `make_params.c`

    This utility creates the IBE parameters needed to encrypt and decrypt
    Topic Values.

- `kms_ctrl.c`

    This is a utility for inquiring about the status of the KMS (is it
    running?) or for telling the KMS to flush its cache, to re-read its
    config file, or to shut down. `kms_ctrl -h` for usage information.

- `print_cache.c`

    This is a debugging utility to print the contents of the KMS's private
    key cache.

- `rand_id.c`

    This is a simple utility for generating a random Client ID. It is
    discussed in the Enrollment section below.

> If you have `doxygen` installed on your system, you can run `make doc` to
  generate documentation in `doc/html/index.html`

## Building

The KMS code uses hyperrealm's `libconfig` library for parsing configuration
files. It is [available from
GitHub](https://github.com/hyperrealm/libconfig). Build and install this
before proceeding to build the KMS.

```bash
$ tar xf libconfig-1.7.3.tar.gz
$ cd libconfig-1.7.3
$ ./configure
$ make
$ sudo make install
```

If you clone `libconfig` from GitHub, be sure to check out the build
instructions in the `INSTALL` file.

KMS also uses wolfSSL to communicate with Clients over TLS-protected
connections. See the README in `../lib` for instructions on installing
wolfSSL support.

The KMS runs under its own userid as a modest effort to keep its
cryptographic secrets away from civilian users. This userid must be `kms` to
keep `Makefile`s happy. Create a userid for the KMS by

```bash
$ sudo adduser kms
Adding user `kms' ...
Adding new group `kms' (1001) ...
Adding new user `kms' (1001) with group `kms' ...
Creating home directory `/home/kms' ...
Copying files from `/etc/skel' ...
New password: 
Retype new password: 
passwd: password updated successfully
Changing the user information for kms
Enter the new value, or press ENTER for the default
	Full Name []: MasQiTT Key Management Server
	Room Number []: 
	Work Phone []: 
	Home Phone []: 
	Other []: 
Is the information correct? [Y/n] y
$
```

Make sure your system is configured to find `libmasqitt.so` at runtime. You
will probably need to set the `LD_LIBRARY_PATH` environment variable as
described in the `../lib` README. Add the following lines somewhere in
`/home/kms/.bashrc` (the trailing "`:`" on `LD_LIBRARY_PATH` is important):

```bash
LD_LIBRARY_PATH="/usr/local/lib:" export LD_LIBRARY_PATH
PATH="${HOME}/bin:${PATH}" export PATH
```

Then it's a simple matter of

```bash
$ cd ..../masqitt
$ make
$ sudo make install
$ su - kms
Password:
kms$ make_params
kms$ exit
$
```

The `make_params` utility creates the IBE values that are needed by Secure
MQTT to encrypt and decrypt Topic Values. It is normally run only once at
installation time.

```bash
$ su - kms
Password:
kms$ make_params
kms$ exit
$
```

The KMS will need a configuration file (`kms.cfg` in the KMS home directory)
to run. See the comments in `kms.cfg` for a description of the configuration
file contents and modify the file as desired.

(See below for notes on testing the KMS.)

## Enrolling Clients

Certification Authority (CA) utilities will have been set up by the `make
install` above if your system has a `kms` user.

See the Certification Authority README in `../ca` for details on
initializing the CA and enrolling Clients.

## Use

You will need to `su` to (or log in as) the KMS user to run the `kms`
command to start the server. `kms -h` provides a usage summary. In most
cases it is preferable to

```bash
$ su - kms
Password:
kms$ kms
```

This runs the KMS in the foreground; add `-d` to have it detach and run in
daemon mode (stdout and stderr are redirected to files named `stdout` and
`stderr` in the KMS home directory and overwrite contents from earlier
runs). Add `-v` or `-vv` to the command line for verbose reporting on
messages received and responses sent.

> Trivia: The default KMS port of 56788 was chosen by mapping phone keys for
  'SMQTT' to numbers, except that 76788 exceeds the maximum 16 bit value of
  a port number so '5' was substitued for 'S'.

If the KMS is started without the `-d` option, typing `^C` will terminate
the KMS in an orderly fashion, writing its cache file before exiting.

`kms_ctrl` (as any user) can be used interact with the KMS:

- `kms_ctrl -i` for information about KMS status
- `kms_ctrl -s` to cleanly shut down the KMS
- `kms_ctrl -d` to have the KMS save its cache to disk
- `kms_ctrl -c` to instruct the KMS to re-read its config file

Add `-q` to suppress output and only return a status (may be useful in
`bash` scripts) or `-v` for more verbose reporting.

Note that `kms_ctrl` must be run on the same system as the KMS. There is no
provision for running it from other systems.

## Testing the KMS

Test programs in `../lib` that communicate with the KMS (pretty much all of
them) use a collection of pre-generated test TLS keys and certificates (in
`../tests/certs`). Before running these tests, use your `sudo` magic to copy
those `*.pem` files to `~/kms/ca` and then `sudo chown kms.kms *` them.

You will also need to replace `~kms/kms.cfg` with the `~kms/kms-test.cfg`
file to match up with the test Clients.
