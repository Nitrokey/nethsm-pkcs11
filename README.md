# PKCS#11 Driver for the Nitrokey NetHSM

## Note

This driver is still an early Proof of Concept implementation that only
implements the functions that are necessary for operating TLS servers like for
example an HTTPS server.

## Building

Please use the [official Go compiler](https://go.dev/doc/install) for compiling the driver, the GNU Go compiler is currently not supported.

## Usage

There is no documentation yet. But you can check out the `p11nethsm.conf` file,
the `test_*.sh` scripts in the `tools/` directory, and the files in
`container/nginx` to get an idea.
