# SnortGo

## Installation

```bash
git clone https://github.com/rogercoll/snortGo.git
cd cmd/snort
go build
```

## Usage

```bash
./snort --iface wlan0 --f ./myrules.conf
```

### Flags

```bash
Flags:
      --f string       Rules file (default "/etc/snort.conf")
  -h, --help           help for snort
      --iface string   Network interface to scan (default "eth0")
```

## Rules file

To seek for any port/address write -1

```yaml
rules:
 - protocol: TCP
   src: 1.1.1.1
   dst: -1
   sport: -1
   dport: -1
 - protocol: TCP
   src: 192.168.1.1
   dst: 192.168.2.34
   sport: -1
   dport: 443
```