# Cómo cambiar la contraseña de Easy Short URL  
# How to change the Easy Short URL password

La contraseña se almacena como hash **bcrypt** en el archivo `.env`.  
Nunca se guarda en texto plano.  

The password is stored as a **bcrypt** hash in the `.env` file.  
It is never stored in plain text.

---

## Pasos para generar una nueva contraseña  
## Steps to generate a new password

### 1. Genera el hash  
### 1. Generate the hash

Ejecuta este comando en el servidor, sustituyendo `TU_NUEVA_CONTRASEÑA`:  
Run this command on the server, replacing `YOUR_NEW_PASSWORD`:

```bash
docker exec -w /tmp web2 php -r "echo password_hash('TU_NUEVA_CONTRASEÑA', PASSWORD_BCRYPT);"
```

Ejemplo de salida:  
Example output:

```
$2y$10$XJFSM3U0OixG.veEDoLI3eADiI/85EnvLqM5z0RKKWhh4QTwkci6i
```

### 2. Edita el archivo `.env`  
### 2. Edit the `.env` file

Abre `/data/dockers/web2/public/.env` y reemplaza el valor de `APP_PASSWORD`:  
Open `/data/dockers/web2/public/.env` and replace the value of `APP_PASSWORD`:

```
APP_USER=admin
APP_PASSWORD=$2y$10$XJFSM3U0OixG.veEDoLI3eADiI/85EnvLqM5z0RKKWhh4QTwkci6i
```

> Pega el hash exactamente como lo genera el comando, sin espacios ni comillas.  
> Paste the hash exactly as generated, without spaces or quotes.

### 3. También puedes cambiar el usuario  
### 3. You can also change the username

Modifica `APP_USER` con el nombre de usuario que quieras:  
Modify `APP_USER` with the username you want:

```
APP_USER=mi_usuario
APP_PASSWORD=$2y$10$...
```

---

## Notas de seguridad  
## Security notes

- El archivo `.env` está bloqueado por `.htaccess` y no es accesible desde el navegador.  
  The `.env` file is protected by `.htaccess` and is not accessible from the browser.  

- Después de **5 intentos fallidos** de login, la IP queda bloqueada **15 minutos**.  
  After **5 failed login attempts**, the IP is blocked for **15 minutes**.  

- Todos los intentos de login quedan registrados en `data/security.log`.  
  All login attempts are logged in `data/security.log`.  

- Usa contraseñas de al menos **12 caracteres** combinando letras, números y símbolos.  
  Use passwords of at least **12 characters**, combining letters, numbers and symbols.
