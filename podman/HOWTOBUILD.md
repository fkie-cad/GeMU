# How to build
Just go to the top level directory and run
```bash
podman build -t gemu -f podman/Dockerfile .
```
Then use `./podman_run.sh` and provide the path to a sample and an output path to run gemu.
