from scapy.all import *
import random, time
# IP
ip=IP(src='192.168.0.11',dst='255.125.164.1') #31.44.8.0   255.192.164.1
# Список пакетов
list_of_packets = []
message = "This is secret message" 
# Конвертируем в байты
massage = bytes(message,encoding='utf-8')
# Заполняем список пакетов
for i in range(0, len(message)-1,2):
    # Случайные 1446 байтов
    useless_bytes = random.randbytes(1000)
    # по 2 байта пэйлоад в SeqNo
    mess_current_1 = (message[i])
    mess_current_2 = (message[i+1])
    # В номер кладем 2 ASCII символа 
    sender = bytes(str(mess_current_1) + str(mess_current_2),encoding='utf-8')
    # Формируем TCP пакет
    TCP_Pkt=TCP(sport=5000, dport=5000, window=251, flags='A', seq=int.from_bytes(sender,byteorder="little"), ack=1)
    # Добавляем пакет
    list_of_packets.append(ip/TCP_Pkt/useless_bytes)
# Отправялем пакеты
for i in range(len(list_of_packets)):
    send(list_of_packets[i])
    if i==0:
        send(list_of_packets[i])
