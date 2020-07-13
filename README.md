## SnortGo

### Temporal

For now, the filename is hardcoded. Inside cmd/ name it `myrules.yaml`.

### Rules file

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