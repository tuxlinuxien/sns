# Simple Name Server

## Block lists

-   [Black-listed Domains](https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts)

## Usage

```
Usage: sns [OPTIONS]

Options:
      --port <PORT>              [default: 53]
      --interface <INTERFACE>    [default: 127.0.0.1]
      --debug <DEBUG>            [default: debug] [possible values: trace, debug, info, warn, error]
      --enable-udp
      --enable-tcp
      --ad-file <AD_FILE>        file path containing domains that will be blocked
      --hosts-file <HOSTS_FILE>  file path of your custom hosts [default: /etc/hosts]
      --nameserver <NAMESERVER>  [default: 8.8.8.8]
  -h, --help                     Print help
  -V, --version                  Print version
```
