# libbpfgo-example

This is an example of writing a small program with [libbpfgo](https://github.com/aquasecurity/tracee/tree/main/libbpfgo), a Go wrapper for libbpf.

To build simply run `make` and run the resulting `simple` binary.

## 1. 測試環境準備
### Kernel
本專案目前只在Ubuntu平台上進行開發與測試。建議測試版本可以使用Ubuntu 21.04。如果使用其他版本的Linux記得使用BTF支援的kenel。確定你的Linux kernel編譯選項CONFIG_DEBUG_INFO_BTF=y kconfig有選定。詳細的Linux版本可以參考libbpf README。

### libbpf
由libbpf原始程式碼編譯
```
git clone https://github.com/libbpf/libbpf/ libbpf
```
編譯libbpf, 例如將libbpf編譯到/build/root這個路徑，可以依據自行設定編譯到不同的位置
```
BUILD_STATIC_ONLY=y PKG_CONFIG_PATH=/build/root/lib64/pkgconfig DESTDIR=/build/root 
```
make install
可以使用本專案的Makefile
```
make libbpf
```
由Ubuntu套件libbpf-dev
```
apt-get install libbpf-dev
```
bpftool
```
apt install linux-tools-common linux-tools-generic
```

## 2. Install packages
```
sudo apt-get update
sudo apt-get install libbpf-dev make clang llvm libelf-dev
```

## 3. Building and running simple
```
make all
sudo ./simple
```

This builds two things:

simple.bpf.o - an object file for the eBPF program
* simple - a Go executable
* The Go executable reads in the object file at runtime. Take a look at the .o file with readelf if you want to see the sections defined in it.

## 4. Docker
To avoid compatibility issues, you can use the Dockerfile provided in this repository.

Build it by your own:

```
docker build -t simple .
```

And the run it from the project directory to compile the program:

```
docker run --rm -v $(pwd)/:/app/:z simple
```
