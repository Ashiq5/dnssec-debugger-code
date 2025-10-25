# Docker Environement for the expirement

To run a single docker container for the environement launch the following command on the root of this repository : 

```
docker compose up
```

## Multiple Workers

To have multiple worker running on the same server launch the following command 

```
docker compose up --scale worker=5
``` 

## Bash access to a container for debugging purposes

In comparaison to the previous version we don't expose port 2222 anymore.

However, sshd is still running and you can connect using the docker container's IP.

You can list the containers' IPs with 

```
docker ps -q | xargs -n 1 docker inspect -f '{{.Name}} - {{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}
```

```
/dnssec-debugger-code-worker-3 - 172.24.0.3
/dnssec-debugger-code-worker-4 - 172.24.0.4
/dnssec-debugger-code-worker-2 - 172.24.0.5
/dnssec-debugger-code-worker-5 - 172.24.0.6
/dnssec-debugger-code-worker-1 - 172.24.0.7
/redis - 172.24.0.2
```