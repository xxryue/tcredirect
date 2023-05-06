# tc redirect by port and add options in ip header testing

You can change dest port for ingress on a server

```
tc qdisc add dev interface-name clsact
tc filter add dev interface-name egress bpf da obj tc_ingress.bpf.o sec tc_egress
tc filter add dev interface-name ingress bpf da obj tc_ingress.bpf.o sec tc_ingress
```


## add options 
Add options for ip packet with tc in "SEC add_tag" 
