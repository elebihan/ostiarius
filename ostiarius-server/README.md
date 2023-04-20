# Ostiarius Server

# Ostiarius Server

The Ostiarius Server is a HTTP server with a REST API that a client can use to
request the permission to run a command.

The permission request should be encrypted using the server public key. Upon
reception, if the request can be properly decrypted, the server will check in
the ``authorizations.toml`` file if the client is authorized to execute the
command and send the response back, encrypted with the client public key.

The private key of the server can be stored in a password-protected PEM file or
in a PKCS#11 token and passed to server via an URL.

## Usage examples

### Start server with private key in file

Assuming the private key is available as a file named
``/etc/ostiarius-server.d/server.privkey.pem``, protected with password "1234",
the server can be started using:

```sh
ostiarius-server -P "file:///etc/ostiarius-server.d/server.privkey.pem"
```

A prompt will appear to enter the password of the private key file. The password
can also be provided using the ``--password`` option:

- ``--password=file:password.txt``, if the password is stored in file
  ``password.txt``.
- ``--password=env:PASSWORD``, if the password is the value of the environment
  variable ``PASSWORD``.
- ``--password=fd:N`` if the password can be read from file descriptor ``N``,
  opened by another program.

### Start server with private key in PKCS#11 token

Assuming the private key is available in a PKCS#11 token named "Ostiarius Token
01" managed by [SoftHSM][SOFTHSM] as "Ostiarius Server Key 01" and that the PIN
is "1234", the server can be started using:

```sh
ostiarius-server -P "pkcs11:token=Ostiarius%20Token%2001;object=Ostiarius%20Server%20Key%2001?module-path=/usr/lib64/libsofthsm2.so"
```

A prompt will appear to enter the PIN for the PKCS#11 token. As mentioned above,
the PIN can also be provided by the ``--password`` option.

### Get server info

```sh
curl -i http://localhost:3000
```

### Request authorization to run a command

```sh
curl -X POST  -H "Content-Type: application/json" -d '{ "name": "Client 2", "command": "uname -a" }' http://localhost:3000/api/v1/authorizations
```

### List granted authorizations

```sh
curl http://localhost:3000/api/v1/authorizations
```

## Annex

### How to create a SoftHSM PKCS#11 token

[SoftHSM][SOFTHSM] is an implementation of a cryptographic store accessible
through a PKCS #11 interface. You can use it to explore PKCS #11 without having
a Hardware Security Module.

#### Installation

On Fedora GNU/Linux systems, [SoftHSM][SOFTHSM] can be installed as follows:

```sh
sudo dnf install -y softhsm p11-kit openssl
```

The user should configure the location of the virtual tokens:

```sh
mkdir -p ~/softhsm/tokens
mkdir -p ~/.config/softhsm2
echo "directories.tokendir = $HOME/softhsm/tokens" > ~/.config/softhsm2/softhsm2.conf
```

#### Token creation

To create a token named "Ostiarius Token 01" with "0000" as PIN for Security
Officer and "1234" as PIN for the user, execute:

```sh
softhsm2-util --init-token --free --label "Ostiarius Token 01" --so-pin "0000" --pin "1234"
```

The output of the command should look like:
```
Slot 0 has a free/uninitialized token.
The token has been initialized and is reassigned to slot 641188937
```

The [p11-kit][P11KIT] project provides tools to interact with PKCS#11 tokens.
Among them, `p11tool` can be used to check the presence of the newly created token:

```sh
p11tool --list-token-urls | grep SoftHSM
```

The output of the command should look like:
```
pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=ca64d19e2637c449;token=Ostiarius%20Token%2001
```

#### RSA private key import

To import the RSA private key for the served named ``tests/server.privkey.pem``
in the token as "Ostiarius Server Key 01", execute:

```sh
p11tool --login --set-pin '1234' \
        --load-privkey=tests/server.privkey.pem \
        --label 'Ostiarius Server Key 01' \
        --mark-sign \
        --mark-decrypt \
        --write \
        pkcs11:token=Ostiarius%20Token%2001
```

To check the key has been properly imported, execute:

```sh
p11tool --login --set-pin '1234' \
        --list-privkeys \
        pkcs11:token=Ostiarius%20Token%2001
```

The output of the command should look like:

```
Object 0:
 	URL: pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=ca64d19e2637c449;token=Ostiarius%20Token%2001;id=%3A%0C%34%20%FF%58%FE%6C%B6%32%95%18%02%5D%42%3C%E8%83%CA%E9;object=Ostiarius%20Server%20Key%2001;type=private
 	Type: Private key (RSA-4096)
 	Label: Ostiarius Server Key 01
 	Flags: CKA_WRAP/UNWRAP; CKA_PRIVATE; CKA_SENSITIVE;
 	ID: 3a:0c:34:20:ff:58:fe:6c:b6:32:95:18:02:5d:42:3c:e8:83:ca:e9
```

The password can also contains special characters:

```sh

softhsm2-util --init-token --free --label "Ostiarius Token 02" --so-pin "0000" --pin ' <>#%+{}|\\^~[]`;/?:@=&$'
```

```sh
p11tool --login --set-pin ' <>#%+{}|\\^~[]`;/?:@=&$' \
        --load-privkey=tests/server.privkey.pem \
        --label 'Ostiarius Server Key 02' \
        --mark-sign \
        --mark-decrypt \
        --write \
        pkcs11:token=Ostiarius%20Token%2002
```

[SOFTHSM]: https://www.opendnssec.org/softhsm/
[P11KIT]: https://p11-glue.github.io/p11-glue/p11-kit.html
