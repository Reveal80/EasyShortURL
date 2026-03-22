# Cómo cambiar la contraseña de Easy Short URL

La contraseña se almacena como hash **bcrypt** en el archivo `.env`.
Nunca se guarda en texto plano.

---

## Pasos para generar una nueva contraseña

### 1. Genera el hash

Ejecuta este comando en el servidor, sustituyendo `TU_NUEVA_CONTRASEÑA`:

```bash
docker exec -w /tmp web2 php -r "echo password_hash('TU_NUEVA_CONTRASEÑA', PASSWORD_BCRYPT);"
```

Ejemplo de salida:
```
$2y$10$XJFSM3U0OixG.veEDoLI3eADiI/85EnvLqM5z0RKKWhh4QTwkci6i
```

### 2. Edita el archivo `.env`

Abre `/data/dockers/web2/public/.env` y reemplaza el valor de `APP_PASSWORD`:

```
APP_USER=admin
APP_PASSWORD=$2y$10$XJFSM3U0OixG.veEDoLI3eADiI/85EnvLqM5z0RKKWhh4QTwkci6i
```

> ⚠️ Pega el hash exactamente como lo genera el comando, sin espacios ni comillas.

### 3. También puedes cambiar el usuario

Modifica `APP_USER` con el nombre de usuario que quieras:

```
APP_USER=mi_usuario
APP_PASSWORD=$2y$10$...
```

---

## Notas de seguridad

- El archivo `.env` está bloqueado por `.htaccess` y no es accesible desde el navegador.
- Después de **5 intentos fallidos** de login, la IP queda bloqueada **15 minutos**.
- Todos los intentos de login quedan registrados en `data/security.log`.
- Usa contraseñas de al menos **12 caracteres** combinando letras, números y símbolos.
