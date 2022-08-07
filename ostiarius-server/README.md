# Ostiarius Server

## Usage examples


### Start server with private key in PKCS#11 token

```sh
ostiarius-server -P "pkcs11:token=Ostiarius%20Token%2001;pin-value=1234;object=Ostiarius%20Server%20Key%2001?module-path=/usr/lib64/libsofthsm2.so"
```

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
