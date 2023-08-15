# send-arp
Ubuntu 22.04에서 테스트 되었습니다.

## Usage
```shell
$ make
$ sudo ./send-arp
syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]
sample: send-arp wlan0 192.168.10.2 192.168.10.1  
```

## Demo
<img src="https://github.com/mainsw/send-arp/blob/main/img/demo1.png">
