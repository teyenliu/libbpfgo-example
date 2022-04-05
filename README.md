# libbpfgo-example

This is an example of writing a small program with [libbpfgo](https://github.com/aquasecurity/tracee/tree/main/libbpfgo), a Go wrapper for libbpf.

To build simply run `make` and run the resulting `simple` binary.


## Install packages
```
sudo apt-get update
sudo apt-get install libbpf-dev make clang llvm libelf-dev
```

Building and running simple
```
make all
sudo ./simple
```

This builds two things:

simple.bpf.o - an object file for the eBPF program
* simple - a Go executable
* The Go executable reads in the object file at runtime. Take a look at the .o file with readelf if you want to see the sections defined in it.

## Docker
To avoid compatibility issues, you can use the Dockerfile provided in this repository.

Build it by your own:

```
docker build -t simple .
```

And the run it from the project directory to compile the program:

```
docker run --rm -v $(pwd)/:/app/:z simple
```
