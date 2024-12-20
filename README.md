# Microsocks-Zig

[Microsocks](https://github.com/rofl0r/microsocks) SOCKS5 server rewritten in Zig.

`microsocks-zig` is based on the [Microsocks](https://github.com/rofl0r/microsocks) code and 
retains the same properties: lightweight, minimal resource usage, 
and gracefully copes with resource depletion.

The goal of this project is to provide a lightweight, cross-platform SOCKS5 server 
that can be easily compiled from source for various architectures and operating systems.

## Supported Socks5 Features
- Authentication: none, password
- IPv4/IPv6/DNS
- TCP

## Installation
### Clone the Repository
```sh
$ git clone https://github.com/berpb/microsocks-zig.git
$ cd microsocks-zig
```
### Install Dependencies
`microsocks-zig` requires the following packages:
- [zig-network](https://github.com/ikskuh/zig-network)
- [zig-clap](https://github.com/Hejsil/zig-clap)

To install them, run:
```sh
$ zig fetch --save git+https://github.com/Hejsil/zig-clap
$ zig fetch --save git+https://github.com/ikskuh/zig-network
```
### Native Build
To build the project for your current platform:
```sh
$ zig build
```
### Cross-Compilation
To cross-compile for a specific target, use the `-Dtarget` option. 
You can run `zig targets` to see the list of available compilation targets.

For example, to build for Windows (x86_64):
```sh
$ zig build -Dtarget=x86_64-windows
```
### Build Modes
You can specify the optimization mode using the `-Doptimize` option. 
Available build modes are:
- `ReleaseSmall`
- `ReleaseFast`
- `ReleaseSafe`
- `Debug`

For example, to build with the `ReleaseSmall` mode:
```sh
$ zig build -Doptimize=ReleaseSmall
```
For more information, refer to the official documentation of [Zig Build System](/https://ziglang.org/learn/build-system/).
## Usage
```sh
$ microsocks-zig -h
    -h, --help
            Display this help and exit.
    -u, --user <str>
            Specify the username for authentication.
    -P, --pass <str>
            Specify the password for authentication. 
    -w, --white_list <str>...
            Allow access without authentication for specified IP addresses.
    -1, --auth_once
            Authenticate once from the current IP address, bypassing further authentications.
```
