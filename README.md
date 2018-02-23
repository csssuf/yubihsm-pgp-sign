# yubihsm-pgp-sign
This is an example of how to create a PGP signature via a YubiHSM2. It is intended to primarily
serve as a test and example for both [yubihsm-rs] and [pretty-good], and as such is essentially a
proof-of-concept that isn't ready to be used.

## Usage
If you want to try it out, you'll need to have a YubiHSM2, and you'll need to have an existing GPG
key you want to import onto the YubiHSM2. In order to do so, you'll also need the `openpgp2pem` tool
from Monkeysphere.
```
$ gpg --export-options export-reset-subkey-passwd --export-secret-keys ${YOUR_SUBKEY_ID}! |
openpgp2pem ${YOUR_SUBKEY_ID} > private_key.pem
```
`private_key.pem` can then be imported onto the YubiHSM2 via `yubihsm-shell`.

[yubihsm-rs]: https://github.com/coreos/yubihsm-rs
[pretty-good]: https://github.com/csssuf/pretty-good
