# Godump - A Simple CLI Packet Capture Tool

Godump is a lightweight, `tcpdump`-like CLI tool written in Go for capturing and filtering network packets. It allows users to monitor network traffic in real-time with protocol and port-based filtering.

## Features
- Capture packets on a specified network interface
- Filter packets by protocol (`TCP/UDP`)
- Filter packets by port number
- Live output mode (`-f`) for real-time packet monitoring
- Graceful shutdown on `Ctrl+C`

## Installation

To install Godump, make sure you have Go installed, then run:

```sh
go install github.com/ametow/godump@latest
```

Or, clone the repository and build it manually:

```sh
git clone https://github.com/ametow/godump.git
cd godump
go build -o godump
```

## Usage

Basic usage:

```sh
godump -i <interface>
```

### Examples

- Capture all packets on `en0`:
  ```sh
  godump -i en0
  ```

- Capture only TCP packets:
  ```sh
  godump -i en0 -P tcp
  ```

- Capture packets on port 8888:
  ```sh
  godump -i en0 -p 8888
  ```

- Live capture for TCP on port 8888:
  ```sh
  godump -i en0 -P tcp -p 8888 -f
  ```

## License
This project is licensed under the MIT License.

## Contributing
Pull requests are welcome! Feel free to open an issue or submit improvements.
