# rbasefind
A brute-force base address scanner based on [@mncoppola's](https://github.com/mncoppola) [basefind.py](https://github.com/mncoppola/ws30/blob/master/basefind.py) & [@rsaxvc's](https://github.com/rsaxvc) [basefind.cpp](https://github.com/mncoppola/ws30/blob/master/basefind.cpp) implemented in rust.

## Features
Scans a flat, 32-bit binary file and attempts to calculate the base address of the image. Looks for ASCII English strings then finds the greatest intersection of all 32-bit words interpreted as pointers and the offsets of the strings.

This works rather well on some ARM (non-thumb) binaries. It's a very simple heuristic that attempts to use as little information about the file as possible from the target binary. As such, it isn't going to work miracles.

### Help
```
USAGE:
    rbasefind [FLAGS] [OPTIONS] <INPUT>

FLAGS:
    -b, --bigendian    Interpret as Big Endian (default is little)
    -h, --help         Prints help information
    -c, --opencl       Use OpenCL for the search
    -V, --version      Prints version information

OPTIONS:
    -n, --maxmatches <LEN>         Maximum matches to display (default is 10)
    -m, --minstrlen <LEN>          Minimum string search length (default is 10)
    -o, --offset <LEN>             Scan every N (power of 2) addresses. (default is 0x1000)
    -t, --threads <NUM_THREADS>    # of threads to spawn. (default is # of cpu cores)

ARGS:
    <INPUT>    The input binary to scan
```

### Example

```bash
time ./rbasefind fw.bin 
Located 2355 strings
Located 372822 pointers
Scanning with 8 threads...
0x00002000: 2195
0x00001000: 103
0x00000000: 102
0x00003000: 101
0x00004000: 90
0x45e95000: 74
0x45e93000: 73
0x00006000: 64
0x00005000: 59
0x45ec3000: 58

real	0m40.937s
user	5m20.908s
sys	0m0.035s
```

0x00002000 was the correct base address for this binary.

For large binaries, the default scan may take too long. The search size can be dialed down, at the expense of "accuracy", via specifying a minimum string length. i.e.,

```
time ./target/release/rbasefind fw_all.bin -m 100
Located 7 strings
Located 372822 pointers
Scanning with 8 threads...
0x00002000: 4
0x2ae7b000: 2
0xffe54000: 1
0xfba46000: 1
0xfb9c3000: 1
0xfb80a000: 1
0xfafe6000: 1
0xfafe0000: 1
0xfae3b000: 1
0xfae13000: 1

real	0m0.149s
user	0m0.751s
sys	0m0.012s
```

## GPU Acceleration

With the `-c` flag you can run the search with OpenCL on the GPU for (sometimes) faster performances, for example:

### CPU
```
ubuntu@VM-0-6-ubuntu:~/rbasefind$ time cargo run --release -- ~/bootloader.elf 
Located 1176 strings
Located 18670 pointers
Scanning with 4 threads...

0x40056000: 19
...

real	4m54.771s
user	1m54.783s
sys	0m16.799s
```
### GPU
```
ubuntu@VM-0-6-ubuntu:~/rbasefind$ time cargo run --release -- -c ~/bootloader.elf 
Located 1176 strings
Located 18670 pointers

0x40056000: 19
...

real	2m25.881s
user	1m53.566s
sys	0m43.867s
```

## TODO
* Some form of auto mode. Detect endianness based on highest intersection. Auto decrease offset in window around highest match.
