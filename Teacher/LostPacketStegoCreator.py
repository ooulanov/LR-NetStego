from scapy.all import *
import random, time
# Стего
Stego = "We all want to be smart" #10
NotStego = random.randbytes(len(Stego))
# IP
ip=IP(src='192.168.0.11',dst='255.125.164.1') 
# Формируем TCP пакет
TCP_Pkt=TCP(sport=5000, dport=5000, window=251, flags='A', seq=1, ack=1)
# Отправляем пакет со стего, который будет потерян
send(ip/TCP_Pkt/Stego)
# Отпраляем пакет без стего
send(ip/TCP_Pkt/NotStego)
