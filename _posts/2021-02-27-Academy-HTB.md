---
layout: post
title: Write-Up Máquina Academy HTB
date: 2021-02-27 16:00 +0800
last_modified_at: 2021-02-27 16:10 +0800
tags: [htb, writeup, linux, laravel, insecure-login]
toc:  true
---

![info-card](/assets/imagenes/2021-02-27-Academy-HTB/AcademyInfoCard.png)

---
## Introducción

La máquina academy es una máquina con una dificultad facil. En esta máquina explotaremos un laravel version 5.x para obtener una rce de bajos privilegios (www-data). Despues encontraremos unas credenciales en un fichero de variables de entorno pertenecientes al servidor web. Con la lista de users de la maquina probaremos esa credencial en cada uno de los usuarios con shell y obtendremos el user. Posteriormente tendremos que realizar un pequeño movimiento lateral para obtener un usuario con el que podremos usar composer y con GTFObins escalaremos privilegios.

---
## Escaneo

```
nmap 10.10.10.215 -p- -sV -sC
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-27 18:17 CET
Nmap scan report for 10.10.10.215
Host is up (0.033s latency).
Not shown: 65532 closed ports
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c0:90:a3:d8:35:25:6f:fa:33:06:cf:80:13:a0:a5:53 (RSA)
|   256 2a:d5:4b:d0:46:f0:ed:c9:3c:8d:f6:5d:ab:ae:77:96 (ECDSA)
|_  256 e1:64:14:c3:cc:51:b2:3b:a6:28:a7:b1:ae:5f:45:35 (ED25519)
80/tcp    open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://academy.htb/
33060/tcp open  mysqlx?
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
|     Invalid message"
|_    HY000
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port33060-TCP:V=7.91%I=7%D=2/27%Time=603A7EE1%P=x86_64-pc-linux-gnu%r(N
SF:ULL,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(GenericLines,9,"\x05\0\0\0\x0b\
SF:x08\x05\x1a\0")%r(GetRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(HTTPOp
SF:tions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(RTSPRequest,9,"\x05\0\0\0\x0b
SF:\x08\x05\x1a\0")%r(RPCCheck,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSVers
SF:ionBindReqTCP,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSStatusRequestTCP,2
SF:B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fI
SF:nvalid\x20message\"\x05HY000")%r(Help,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")
SF:%r(SSLSessionReq,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01
SF:\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(TerminalServerCookie
SF:,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(TLSSessionReq,2B,"\x05\0\0\0\x0b\x
SF:08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"
SF:\x05HY000")%r(Kerberos,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(SMBProgNeg,9
SF:,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(X11Probe,2B,"\x05\0\0\0\x0b\x08\x05\
SF:x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY0
SF:00")%r(FourOhFourRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LPDString,
SF:9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LDAPSearchReq,2B,"\x05\0\0\0\x0b\x0
SF:8\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\
SF:x05HY000")%r(LDAPBindReq,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(SIPOptions
SF:,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LANDesk-RC,9,"\x05\0\0\0\x0b\x08\x
SF:05\x1a\0")%r(TerminalServer,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(NCP,9,"
SF:\x05\0\0\0\x0b\x08\x05\x1a\0")%r(NotesRPC,2B,"\x05\0\0\0\x0b\x08\x05\x1
SF:a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000
SF:")%r(JavaRMI,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(WMSRequest,9,"\x05\0\0
SF:\0\x0b\x08\x05\x1a\0")%r(oracle-tns,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r
SF:(ms-sql-s,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(afp,2B,"\x05\0\0\0\x0b\x0
SF:8\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\
SF:x05HY000")%r(giop,9,"\x05\0\0\0\x0b\x08\x05\x1a\0");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 49.60 seconds
```
En esta máquina nos encontramos 3 puertos abiertos:
* Puerto 22: SSH
* Puerto 80: HTTP (Apache 2.4.41)
* Puerto 33060

### Puerto 22
En el puerto 22 nos encontramos con un servidor SSH. En un principio no seria explotable.

### Puerto 80
En el puerto 80 nos encontramos con un servidor Apache 2.4.41.

### Puerto 33060
En el puerto 33060 nos encontramos con lo que parece ser un servidro mysql. Por ahora no lo podemos explotar ya que no tenemos ningun tipo de credencial y tampoco podemos determinas a simple vista la versión que corre.

---
## enumeración

Una vez accedemos al servidor web añadiendo el dominio al fichero /etc/hosts, vemos una pagina en la que nos encontramos un una pagina de login y otra de register. Ya que tenemos una pagina de register vamos a registrarnos y ver con burpsuite como lo gestiona.
* request original:
    ``` 
    POST /register.php HTTP/1.1
    Host: academy.htb
    User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 44
    Origin: http://academy.htb
    Connection: close
    Referer: http://academy.htb/register.php
    Cookie: PHPSESSID=csnk1gf35gpjq9u8gnng2fkiv2
    Upgrade-Insecure-Requests: 1
    DNT: 1
    Sec-GPC: 1

    uid=test&password=test&confirm=test&roleid=0
    ```
Si cambiamos el role id por 1 vemos que nos crea la cuenta correctamente. Esto puede ser señal de que hay varios roles dentro de la plataforma y seguramente haya algunas paginas en las que los users de role ID 0 no puedan acceder. Para ver un mapa mas completo de la web y descubrir directorios que no podamos ver a simple vista vamos a utilizar la herramienta [gobuster](https://github.com/OJ/gobuster) para buscar directorios. En este caso utilizo esta herramienta porque en lo personal es la que mas me gusta. Tambien podriamos utilizar herramientas más orientadas a fuzzing como por ejemplo [wfuzz](https://github.com/xmendez/wfuzz) o [ffuf](https://github.com/ffuf/ffuf).

![AcademyWebDiscovery](/assets/imagenes/2021-02-27-Academy-HTB/AcademyWebDiscovery.png)

Como podemos ver, tenemos admin.php que llama mucho la atención, ya que puede contener algún tipo de panel de gestión. En este caso si accedemos con las credenciales del usuario que hemos creado anteriormente, veremos una página con lo que parece ser una lista de tareas. Una de ellas todavía no esta realizada y hace referencia a un subdomino.

![AcademyAdminPhp](/assets/imagenes/2021-02-27-Academy-HTB/AcademyAdminPhp.png)

## Explotación

Ya que hemos descubierto un posible subdominio vamos a añadirlo a /etc/hosts y vamos a acceder.

Una vez hemos accedido, nos encontramos con un servidor laravel el cual nos da mucha informacion de debug.

Sabiendo la tencnología que esta corriendo vamos a ver si decubrimos algun exploit para este servicio. 

![AcademyExploitSearch](/assets/imagenes/2021-02-27-Academy-HTB/AcademyExploitSearch.png)

Vamos a clonar el repositorio a nustra máquina para explotar la [vulnerabilidad](https://nvd.nist.gov/vuln/detail/CVE-2018-15133).

Para la explotación vamos a necesitar simplemente el valor del campo app_key. 

La Vulnerabilidad se produce por una deserialización en el X-XSRF-TOKEN el cual se procesa en el componente Illuminate/Encryption/Encrypter.php.

![AcademyExploitLaravel](/assets/imagenes/2021-02-27-Academy-HTB/AcademyExploitLaravel.png)

Con esto ya podríamos ejecutar comandos como usuario www-data.
Vamos a hacer una enumeracion inicial basica, ya que solomente tenemos una rce y no una shell interactiva.

Lo primero que vamos a hacer es leer el fichero /etc/passwd para ver que usuarios tenemos en el sistema.

![AcademyUsers](/assets/imagenes/2021-02-27-Academy-HTB/AcademyUsers.png)

Una veza tenemos esto, vamos a comprobar los directorios que estan alrededor de el lugar en el que estamos ejecutando los comandos, que en este caso es el directorio /var/www/html/htb-academy-dev-01/public.

![AcademyLsEnvDir](/assets/imagenes/2021-02-27-Academy-HTB/AcademyLsEnvDir.png)

El fichero .env es muy interesante, ya que puede contener mucha información como por ejemplo passwords.
en este caso no contiene ninguna password valida, ya que este fichero .env es una copia exacta del fichero .env.example salvo porque el fichero .env contiene la app_key.

Si tenemos un fichero .env en la carpeta que corresponde con el laravel, vamos a ver si en la web principal tambien tenemos un fichero .env.

![AcademyLsAcademy](/assets/imagenes/2021-02-27-Academy-HTB/AcademyLsAcademy.png)

Efectivamente tenemos un fichero llamado .env. Vamos a ver que contiene.

```
$ cat /var/www/html/academy/.env
APP_NAME=Laravel
APP_ENV=local
APP_KEY=base64:dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=
APP_DEBUG=false
APP_URL=http://localhost

LOG_CHANNEL=stack

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=academy
DB_USERNAME=dev
DB_PASSWORD=mySup3rP4s5w0rd!!

BROADCAST_DRIVER=log
CACHE_DRIVER=file
SESSION_DRIVER=file
SESSION_LIFETIME=120
QUEUE_DRIVER=sync

REDIS_HOST=127.0.0.1
REDIS_PASSWORD=null
REDIS_PORT=6379

MAIL_DRIVER=smtp
MAIL_HOST=smtp.mailtrap.io
MAIL_PORT=2525
MAIL_USERNAME=null
MAIL_PASSWORD=null
MAIL_ENCRYPTION=null

PUSHER_APP_ID=
PUSHER_APP_KEY=
PUSHER_APP_SECRET=
PUSHER_APP_CLUSTER=mt1

MIX_PUSHER_APP_KEY="${PUSHER_APP_KEY}"
MIX_PUSHER_APP_CLUSTER="${PUSHER_APP_CLUSTER}"
```
En este caso si que tenemos una password con mas sentido que la del otro fichero .env.

viendo tambien el fichero /etc/passwd no vemos ningun user llamado dev, pero podemos intentar buscar una posible reutilizacion de credenciales para alguno de los users.

Para esto, vamos a meter todos los username a un fichero y con hydra vamos a testear la password que hemos encontrado.

![AcademyUsercry0lit3PassHydra](/assets/imagenes/2021-02-27-Academy-HTB/AcademyUsercry0lit3PassHydra.png)

Acabamos de encontrar que la password es valida para el usuario cry0l1t3. Vamso a iniciar sesion porssh y a enumerar.

```
Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-52-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun 28 Feb 2021 12:03:31 PM UTC

  System load:             0.0
  Usage of /:              38.1% of 13.72GB
  Memory usage:            16%
  Swap usage:              0%
  Processes:               227
  Users logged in:         0
  IPv4 address for ens160: 10.10.10.215
  IPv6 address for ens160: dead:beef::250:56ff:feb9:5d0a


89 updates can be installed immediately.
42 of these updates are security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed Aug 12 21:58:45 2020 from 10.10.14.2
$ ls -al
total 32
drwxr-xr-x 4 cry0l1t3 cry0l1t3 4096 Aug 12  2020 .
drwxr-xr-x 8 root     root     4096 Aug 10  2020 ..
lrwxrwxrwx 1 root     root        9 Aug 10  2020 .bash_history -> /dev/null
-rw-r--r-- 1 cry0l1t3 cry0l1t3  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 cry0l1t3 cry0l1t3 3771 Feb 25  2020 .bashrc
drwx------ 2 cry0l1t3 cry0l1t3 4096 Aug 12  2020 .cache
drwxrwxr-x 3 cry0l1t3 cry0l1t3 4096 Aug 12  2020 .local
-rw-r--r-- 1 cry0l1t3 cry0l1t3  807 Feb 25  2020 .profile
-r--r----- 1 cry0l1t3 cry0l1t3   33 Feb 27 17:13 user.txt
$ cat user.txt
5cbb1c94b7d247a5d13e3c83ec10f85b
```

Tenemos el User. 

## Movimiento lateral

Si ejecutamos el comando id, vemos que pertenecemos al grupo adm. Este grupo es muy interesante, ya que tiene permisos para leer los logs del sistema.

Con la herramienta aureport podemos analizar los logs de sistema de una manera rapida y eficiente.

En este caso, tenemos que hacer un movimiento lateral al usuario mrb3n.

![AcademyMrb3nPassword](/assets/imagenes/2021-02-27-Academy-HTB/AcademyMrb3nPassword.png)

Con ese comando, lo que hacemos es extraer las teclas que se han pulsado en una session de TTY. En este caso, obtenemos las creds del usuario mrb3n.

## Escalada de privilegios

Una vez hemos accedido con el usuario mrb3n vamos a ver su podemos ejecutar comandos con sudo y escalar privilegios por esa via.


![AcademySudo-l](/assets/imagenes/2021-02-27-Academy-HTB/AcademySudo-l.png)

Como podemos ver, podemos ejecutar el comando composer con privilegios de root ya que podemos usarlo con sudo.


Para la explotación, vamos a consultar la web de [GTFObins](https://gtfobins.github.io).

![AcademySudoGTFObins](/assets/imagenes/2021-02-27-Academy-HTB/AcademySudoGTFObins.png)

![AcademyRoot](/assets/imagenes/2021-02-27-Academy-HTB/AcademyRoot.png)

Ya somos root.
