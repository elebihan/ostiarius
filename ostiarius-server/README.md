# Ostiarius Server

## Usage examples

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
