#!/bin/bash

if [ $# -ne 2 ]; then
  echo "Usage: ./podman_run.sh <path to sample> <output_folder>"
  exit 1
else
  podman run --rm \
    -v ~/VM_Images/:/images \
    -v $(dirname $1):/samples \
    -v $2:/output \
    -it gemu:latest python3 /gemu/gemu/run_sandbox_docker.py --time 20 --sample /samples/$(basename $1)

fi

