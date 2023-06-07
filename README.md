# Ostiarius - Simple centralized command execution management

This is a simple client/server system where the client asks for the
authorization to execute a command to a server, by submitting a challenge
using a REST API. If the challenge succeeds, the client can execute the
command.

# Building instructions

This project is written in Rust, so you'll need to install a [Rust
toolchain][rust] to build it.

Client and server can easily be built using:


```sh
cargo build --release
```

Cross-compiling client and server fo different architectures can be done using
[cross][cross]. For example, to compile the client for an ARM target and the
server for MS Windows, execute:

```sh
cross build --target x86_64-pc-windows-gnu -p ostiarius-server
cross build --target arm-unknown-linux-musleabi -p ostiarius-client
```

# Keys and authorizations list

To run, the server needs:

- a RSA-4096 private key (``server.privkey.pem``)
- a TOML-formatted file (``authorizations.toml``) containing the list of the
  authorized clients with the commands and RSA-4096 public key. For example:

```toml
[[clients]]
name = "Client 1"
pub_key = """
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvPgcoaGScX4Hwu6MXBUI
NCvz+HNIKzro5GZGVW3/zJVvwee7E0dGC5CU/QVP9QxD8uoOawmY8nQoXQYX278Q
JG+QrUupiINrODMQ1qLagT6d9y8ODo2kPD07VQFVW6FSIKYe3GuvFSZ/Kdk3O4Ci
/A9fTJO9O8oquVyxI++BMnvgy93Ed2nBX9pUk22FeRbfYMQc9IEhJOaZ4aTApmOf
BOLUtKyFzFMGj4ZaZVbzJaPxiPTEZdFMRBq/4B4KvKIqo4uqSHttBdHUP1mPNqhn
d14eWcuGIwrXnlOILSdFPV3SpfFv7N6V1vyaGZ6/htnGHJP6wKCxEsnnMh2NVOZF
U59utWIBndYpun0uzRn39b+iJj/Deo3N/JhJnclCgW3EmA1TuaRHr3S5UItlHYe7
7w511DWaUvHeFlPLwssUiMTOvq6EyZGb5+kEOqNU182V2Qy3q+oHE+iJrGm3EvX5
OrUmaZcCpgfwOsH61+O5oJYgtNVPeGMK47OHsgksulKHEYF+twjzgrblm2UMPNS9
tIbew5uNOjzN9SIVVU23OBZ2NEIg0bp2gqhDb0HodBK0TPfdLh2UDdTQ5HOmx1Ft
eiKelWrzaBhXiUwymjDWp4BpPbAXSRSYn4q3Cp6pK/roMhfAx4BjgydOFl1bHFsG
hqxaKKp7ROkxDCuYhmHh7JECAwEAAQ==
-----END PUBLIC KEY-----
"""
commands = ["date"]
# ...
```

To run, the client needs:

- a RSA-4096 private key (``client.privkey.pem``)
- the server RSA-4096 public key (``server.pubkey.pem``)

All the keys can be generated using:

```sh
openssl genrsa -aes256 -out server.privkey.pem  4096
openssl rsa -in server.privkey.pem -pubout -out server.pubkey.pem
openssl genrsa -out client.privkey.pem 4096
openssl rsa -in client.privkey.pem -pubout -out client.pubkey.pem
```

Do not forget to store the password of the private key somewhere safe, as it
will be used when running the programs.

# Usage example

Start server on PC with address 192.168.1.10 on port 3000:

```sh
ostiarius-server --address 192.168.1.10 --port 3000
```

Start client with name "Client 1" to check for the authorization to execute `ls /etc`:

```sh
ostiarius-client --name "Client 1" http://192.168.1.10:3000 'ls /etc'
```

The server can also use a private key stored in a PKCS#11 token. See
[ostiarius-server/README.md](ostiarius-server/README.md) for details.

# License

Copyright (c) 2022 Eric Le Bihan

This program is distributed under the terms of the MIT License.

See the [LICENSE](LICENSE) file for license details.

[cross]: https://github.com/cross-rs/cross
[rust]: https://www.rust-lang.org/
