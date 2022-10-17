sudo apt-get update
sudo apt-get install sendip
正常包：
udp 53：
sendip -v -p ipv4 -is 源ip -id 目的ip -p udp -us 源端口 -ud 53 -d 数据 目的ip
tcp 80/443：
sendip -v -p ipv4 -is 源ip -id 目的ip -p tcp -ts 源端口 -td 80 -d 数据 目的ip
sendip -v -p ipv4 -is 源ip -id 目的ip -p tcp -ts 源端口 -td 443 -d 数据 目的ip
icmp：
sendip -v -p ipv4 -is 源ip -id 目的ip -p icmp -d 0xcafecafecafe 目的ip
异常包：
./tcp  源ip 源端口 目的ip 目的端口 数据
./icmp  目的ip
