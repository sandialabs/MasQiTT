# MasQiTT

![MasQiTT logo](MasQiTT.png)

## Description

This is the repo for Sandia's MasQiTT reference implementation code
of the Secure MQTT protocol.

For more detailed information, see the individual `README`s in (most of)
these subdirectories. In case of discrepancies between what is said in
`README` files and the User Guide, consider the User Guide the better
option.

- `lib` contains the core MasQiTT code implementing Secure MQTT.

- `kms` contains the Key Management Server code base.

- `ca` contains the Certification Authority utilities.

Additionally,

- `include` holds the include files used by code in `lib` and `kms`.

- `tests` contains programs to test the `libmasqitt` library routines.

- `examples` includes worked examples of Mosquitto Clients modified to
  work with MasQiTT as well as a conversion guide.

## Maintenance

Building and running Secure MQTT can be accomplished by following the
instructions in the `lib`, `kms`, and `ca` `README`s (in that order). This
is especially important the first time building Secure MQTT as you may need
to install some supporting libraries.

For convenience after the first time building Secure MQTT, the `Makefile` in
this directory can be used to

- `make all` (or simply `make`) runs `make all` in each of the subordinate
  directories (in the correct order).

- `make test` runs `make test` in each of the subordinate directories
  (in the correct order).

- `sudo make install` installs `libmasqitt.so` in `/usr/local/lib` and
  KMS components in the KMS home directory.

- `sudo make uninstall` removes the files created by `make install`.

- `make clean` runs `make clean` in each of the subordinate directories.

- `make realclean` runs `make realclean` in each of the subordinate directories.

- `make help` lists the available top-level make targets.

- `make tar` assembles a tar image (`masqitt.tgz`) of all the MasQiTT
  code. You should be able to

  ```bash
  $ mkdir foo
  $ cd foo
  $ tar xf ..../masqitt.tgz
  $ make
  $ sudo make install
  ```
