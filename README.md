# Making Test Roots

The make_test_root.py program creates the files you need to set up a a test (fake) root server that
has the features you want.
It is useful for testing recursive resolvers against a root with different features than the current
DNS root.
For example, you might want to create a root that has three ZSKs to see how that affects priming.
The resulting root has all the configuration needed for running under recent versions
of BIND.

## Installation

Install by cloning from GitHub.
You need to have Python3 installed.
You also need to have BIND utilities such as named-checkconf and dnssec-keygen installed;
this is usually done by installing "bindutils" or "bind9" from your
packaging system.

## Running

The `make_test_root.py` command takes one argument, the name of the configuration file.
The command prints its status on standard output,
and keeps an extensive running log in `log_for_make_test_root.txt`.

The main result of running the command is a directory with associated files.
These include all of the keys created and a named.conf for serving with BIND.
They also include files that are used on recursive resolvers that will use this
test root as a server, such as DS and DNSKEY records for trust anchors and a
root.hints file to install on those resolvers.

## Configuration

See the `test-root-config.template` file.
It is formatted as a typical "ini" file with a single section called `[confs]`.
The options `directory`, and at least one of `ipv4` and/or `ipv6`, are required.

The `wrong-trust-anchor` option, a boolean, is probably the only one that needs
additonal description. If set to `true`, when the command emits a trust anchor
for a root with two KSKs, the trust anchor will _not_ be the correct trust
anchor: it will be for the KSK that did not sign the ZSKs. This is probably
only useful for testing a KSK rollover such as that on October 11, 2017.

## License

See the `LICENSE` file.

## Future features

* The root zone is now always signed with one ZSK; this could be more flexible.

* Add algorithims other than RSA.

* The zone that is used for the root server naming should be signed like .net is signed.
