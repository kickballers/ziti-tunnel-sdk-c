# Run The OpenZiti Tunneler with Docker

## Configuring the Ziti Identity

It is necessary to supply a Ziti identity enrollment token or an enrolled Ziti identity configuration JSON to the container as a volume-mounted file or as environment variables. The following variable, volumes, and files are common to both container images described below.

### Configuration with Environment Variable

- `ZITI_IDENTITY_JSON`: The JSON string of the Ziti identity. This overrides other methods of supplying the Ziti identity JSON. It is not advisable to mount a volume on the container filesystem when using this method because the Ziti identity is written to a temporary file and will cause an error if the file already exists.

### Configuration with Files from Mounted Volume

You may bind a host directory to the container filesystem in `/ziti-edge-tunnel` as a means of supplying the token JWT file or configuration JSON file. If a token JWT file is supplied then it will be enrolled on first container startup and the identity configuration JSON file will be written in the same location named like `${ZITI_IDENTITY_BASENAME}.json`.

- `ZITI_IDENTITY_BASENAME`: the file basename (without the filename suffix) of the enrollment (.jwt) and identity (.json) files the tunneler will use
- `ZITI_ENROLL_TOKEN`: Optionally, you may supply the enrollment token JWT as a string if `${ZITI_IDENTITY_BASENAME}.jwt` is not mounted
- `ZITI_IDENTITY_WAIT`: Optionally, you may configure the container to wait max seconds for the JWT or JSON file to appear in the mounted volume

## Container Image `openziti/ziti-host`

This image runs `ziti-edge-tunnel run-host` on the Red Hat 8 Universal Base Image to optimize deployability within the Red Hat ecosystem e.g. OpenShift. The `ziti-edge-tunnel run-host` hosting-only mode of the Linux tunneler is useful as a sidecar for publishing containerized servers located in a Docker bridge network (use network mode `bridge`) or any other server running in the Docker host's network (use network mode `host`).

This image is used by [the eponymous Helm chart, `ziti-host`](https://openziti.github.io/helm-charts/).

See the [the Linux tunneler doc](https://openziti.github.io/ziti/clients/linux.html) for general info about the Linux tunneler that is installed in this container image.

### Image Tags for `openziti/ziti-host`

The `openziti/ziti-host` image is published in Docker Hub and manually updated for some new releases. You may subscribe to `:latest` (default) or pin a version for stability e.g. `:0.19.11`.

### Dockerfile for `openziti/ziti-host`

The Dockerfile for `openziti/ziti-host` is [./Dockerfile.ziti-host](./Dockerfile.ziti-host). There's no build or test automation for this image yet.

### Examples using `openziti/ziti-host`

Publish servers that are reachable on the Docker host's network e.g. `tcp:localhost:54321`:

```bash
# identity file on Docker host is mounted in container: /opt/openziti/etc/identities/my-ziti-identity.json
docker run \
  --name ziti-host \
  --rm \
  --network=host \
  --env ZITI_IDENTITY_BASENAME="my-ziti-identity" \
  --volume /opt/openziti/etc/identities:/ziti-edge-tunnel \
  openziti/ziti-host
```

Publish servers inside the same Docker bridge network e.g. `tcp:my-docker-service:80`:

```bash
# identity file on Docker host is stuffed in env var: /opt/openziti/etc/identities/my-ziti-identity.json
docker run \
  --name ziti-host \
  --rm \
  --network=my-docker-bridge \
  --env ZITI_IDENTITY_JSON="$(< /opt/openziti/etc/identities/my-ziti-identity.json)" \
  openziti/ziti-host
```

This example uses the included Docker Compose project to illustrate publishing a server container to your OpenZiti Network.

1. Create an OpenZiti Config with type `intercept.v1`.

    ```json
    {
        "addresses": [
            "hello-docker.ziti"
        ],
        "protocols": [
            "tcp"
        ],
        "portRanges": [
            {
            "low": 80,
            "high": 80
            }
        ]
    }
    ```

1. Create an OpenZiti Config with type `host.v1`

    ```json
    {
        "port": 80,
        "address": "hello",
        "protocol": "tcp"
    }
    ```

1. Create a service associating the two configs with a role attribute like "#HelloServices"
1. Create an identity for your client tunneler named like "MyClient" and load the identity
1. Create an identity named like "DockerHost" and download the enrollment token in the same directory as `docker-compose.yml` i.e. "DockerHost.jwt"
1. Create a Bind service policy assigning "#HelloServices" to be bound by "@DockerHost"
1. Create a Dial service policy granting access to "#HelloServices" to your client tunneler's identity "@MyClient"
1. Run the demo server

    ```bash
    docker-compose up --detach hello
    ```

1. Run the tunneler

    ```bash
    ZITI_IDENTITY_JSON="$(< /tmp/my-ziti-id.json)" docker-compose up --detach ziti-host
    # debug
    ZITI_IDENTITY_JSON="$(< /tmp/my-ziti-id.json)" docker-compose run ziti-host run-host --verbose=4
    ```

1. Access the demo server via your OpenZiti Network: [http://hello-docker.ziti](http://hello-docker.ziti)

Please reference [the included Compose project](docker-compose.yml) for examples that exercise the various container images, options, and run modes.

## Container Image `openziti/ziti-edge-tunnel`

This image runs `ziti-edge-tunnel run`, the OpenZiti tunneler, on a Debian Linux base. This run mode provides a Ziti nameserver and transparent proxy that captures
network traffic destined for Ziti services.

See the [the Linux tunneler doc](https://openziti.github.io/ziti/clients/linux.html) for general info about the Linux tunneler that is installed in this container image.

This container image requires access to a Ziti enrollment token (JWT), and typically uses a persistent
volume mounted at `/ziti-edge-tunnel` to persist the permanent identity JSON configuration file that is created
when the one-time enrollment token is consumed.

### Tags for `openziti/ziti-edge-tunnel`

The container image `openziti/ziti-edge-tunnel` is published in Docker Hub and frequently updated with new releases. You may subscribe to `:latest` (default) or pin a version for stability e.g. `:0.19.11`.

### Dockerfile for `openziti/ziti-edge-tunnel`

The main Dockerfile for `openziti/ziti-edge-tunnel` is [./Dockerfile](./Dockerfile). This image is typically built with the BuildKit wrapper script [./buildx.sh](./buildx.sh) and there is not yet any build or test automation for this image.

### Examples using `openziti/ziti-edge-tunnel`

Transparent Proxy `run` mode configures an OpenZiti nameserver running on the local device and captures any layer 4 traffic that matches an authorized service destination.

```bash
# current directory contains enrollment token file ziti_id.jwt
docker run \
    --name ziti-tun \
    --network host \
    --privileged \
    --volume ${PWD}:/ziti-edge-tunnel/ \
    --volume "/var/run/dbus/system_bus_socket:/var/run/dbus/system_bus_socket" \
    --device "/dev/net/tun:/dev/net/tun" \
    --env ZITI_IDENTITY_BASENAME=ziti_id \
    openziti/ziti-edge-tunnel
```

This example uses the Docker Compose project included in this repo.

```bash
# enrolled identity file ziti_id.json is in the same directory as docker-compose.yml
ZITI_IDENTITY_BASENAME=ziti_id docker-compose run ziti-tun
```
