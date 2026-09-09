# Zero-Trust Authentication SRP Prototype

Este proyecto es un prototipo didáctico de autenticación Zero-Trust basado en SRP-6a (Secure Remote Password), implementado con:

- Frontend: HTML5 + CSS + JavaScript puro
- Backend: PHP 8.2 + API REST
- Criptografía del cliente: cálculo local en navegador
- Criptografía del backend: phpseclib v3 (`BigInteger`)
- Persistencia: archivo local `db.json`

La intención principal es demostrar que la contraseña nunca se envía en texto plano, y que la autenticación se realiza sobre un secreto derivado criptográficamente, sin exponer la contraseña original en la red.

---

## 1. Objetivo del prototipo

El sistema busca cumplir estas condiciones:

1. La contraseña no viaja en claro.
2. El servidor no recibe un hash simple de la contraseña en la red.
3. La autenticación se hace mediante un protocolo de intercambio de secretos criptográfico.
4. El usuario registra una credencial de autenticación sin enviar la contraseña al backend.
5. La validación final se realiza por comprobación de un valor de prueba generado a partir del secreto compartido.

Este es un prototipo académico y no sustituye una implementación de producción de SRP con validación completa de todos los parámetros y controles de seguridad de un sistema real.

---

## 2. Arquitectura general

El proyecto está dividido en cuatro bloques principales:

### Frontend
Archivo principal: [index.html](index.html)

Responsable de:

- recoger usuario y contraseña
- derivar la credencial SRP del lado del cliente
- generar `A`, `x`, `verifier`, `S` y `M1`
- hacer las llamadas `fetch()` a la API
- mostrar la consola de auditoría con los payloads enviados

### Backend
Archivo principal: [api.php](api.php)

Responsable de:

- aceptar acciones `register`, `challenge` y `verify`
- guardar usuarios en `db.json`
- validar credenciales
- generar el desafío SRP (`B` y `b`)
- verificar la prueba del cliente (`M1`)
- devolver un token si la autenticación es correcta

### Persistencia
Archivo: [db.json](db.json)

Simula una base de datos local con este formato:

```json
[
  {
    "username": "alice",
    "salt": "ABCD1234...",
    "verifier": "..."
  }
]
```

### Dependencias
Archivo: [composer.json](composer.json)

Se usa `phpseclib/phpseclib` para operar con enteros grandes `BigInteger`, especialmente en aritmética modular de SRP.

---

## 3. Principios de seguridad que intenta demostrar

### 3.1 La contraseña no se transmite en claro

Durante el registro y el login, el navegador nunca manda la cadena original de la contraseña al servidor.

En su lugar, se deriva un valor de autenticación a partir de:

- `username`
- `password`
- `salt`

Este valor queda encapsulado dentro del cálculo SRP.

### 3.2 El servidor no guarda la contraseña directamente

El backend guarda solamente:

- `username`
- `salt`
- `verifier`

Esto es compatible con la idea del protocolo SRP: el servidor guarda un valor derivado criptográfico, no la contraseña original.

### 3.3 El secreto compartido se calcula en ambos lados

El protocolo genera un secreto compartido `S` en ambos extremos, pero cada lado lo calcula a partir de valores distintos:

- el cliente usa `a`, `A`, `x`, `u`, `B`
- el servidor usa `b`, `B`, `u`, `A`, `v`

Solo si ambos lados usan los mismos valores secretos y las mismas ecuaciones, el valor coincide.

---

## 4. Flujo de trabajo completo del prototipo

## 4.1 Registro de usuario

### Paso 1. El usuario rellena formulario
En [index.html](index.html) se toma:

- username
- password

### Paso 2. Generación de salt
El navegador genera un valor aleatorio llamado `saltHex`.

Esto evita que dos usuarios con la misma contraseña produzcan el mismo valor de verificador.

### Paso 3. Derivación del verificador
El cliente calcula:

- `x = H(salt || H(username:password))`
- `verifier = g^x mod N`

Es decir, el navegador genera un valor matemático que será almacenado por el servidor como representación de la credencial, sin enviar la contraseña.

### Paso 4. Envío al backend
Se hace un `fetch()` a:

```text
POST /api.php?action=register
```

con el JSON:

```json
{
  "username": "alice",
  "salt": "A1B2C3...",
  "verifier": "..."
}
```

### Paso 5. Guardado del usuario
En [api.php](api.php), `register` valida que el usuario no exista y escribe este registro en `db.json`.

---

## 4.2 Login / desafío SRP

### Paso 1. El cliente genera `a` y `A`
En el navegador se genera un secreto aleatorio `a` y se calcula:

```text
A = g^a mod N
```

Ese valor se envía al servidor como parte del desafío inicial.

### Paso 2. Petición al servidor
Se hace:

```text
POST /api.php?action=challenge
```

con:

```json
{
  "username": "alice",
  "A": "..."
}
```

### Paso 3. El servidor busca al usuario
En [api.php](api.php), la función `findUserByName()` carga todos los usuarios del JSON y busca el registro específico.

### Paso 4. El servidor genera `b` y `B`
El servidor crea un valor secreto `b` y calcula:

```text
B = (k * v) + (g^b mod N) mod N
```

donde:

- `v` es el verifier del usuario
- `k` es una constante SRP
- `N` es el módulo primo del grupo SRP
- `g` es el generador

### Paso 5. El servidor guarda la sesión SRP
Se almacena temporalmente en `$_SESSION['srp']`:

- username
- A
- B
- b
- salt
- verifier

Esto permite al servidor reconstruir el secreto compartido durante la verificación final.

### Paso 6. La respuesta al cliente
El servidor responde con:

```json
{
  "success": true,
  "salt": "...",
  "B": "..."
}
```

El cliente ya tiene el `salt` y el `B` del servidor.

---

## 4.3 Cálculo del secreto compartido del cliente

Una vez recibido `B`, el cliente calcula:

### Paso 1. Derivar `x`
```text
x = H(salt || H(username:password))
```

### Paso 2. Calcular `u`
```text
u = H(A || B)
```

### Paso 3. Calcular el secreto compartido
La fórmula prototípica del cliente es:

```text
S = (B - k * g^x)^(a + u * x) mod N
```

Esto es el punto clave del protocolo: el secreto compartido se construye sin enviar la contraseña en claro.

### Paso 4. Generar la prueba `M1`
El cliente produce un valor de prueba destinado a demostrar que tiene el secreto correcto.

En la implementación actual se usa una prueba derivada del secreto compartido con `A`, `B` y la salida de hash.

Se envía al backend como:

```json
{
  "username": "alice",
  "M1": "..."
}
```

---

## 4.4 Verificación del servidor

Cuando el servidor recibe `M1`, ejecuta la validación:

### Paso 1. Recupera la sesión
Lee la sesión SRP guardada:

- A
- B
- b
- salt
- verifier

### Paso 2. Recalcula el secreto compartido
El backend hace la operación equivalente usando:

- `A`
- `B`
- `b`
- `verifier`
- `u = H(A || B)`

y calcula el valor del secreto compartido `S` del lado del servidor.

### Paso 3. Recalcula `M1`
El servidor recalcula la prueba esperada y la compara con la enviada por el cliente.

Si coincide, entonces el cliente demuestra saber el secreto correcto sin haberlo enviado explícitamente en la red.

### Paso 4. Emite un token
Si la prueba es válida, el backend responde:

```json
{
  "success": true,
  "message": "Autenticación SRP verificada correctamente.",
  "token": "..."
}
```

---

## 5. Cómo funciona la consola de auditoría

El frontend incluye una sección llamada "Consola de Auditoría" en [index.html](index.html).

Su objetivo es mostrar exactamente los payloads JSON que salen por `fetch()`, sin revelar la contraseña en texto plano.

Ejemplo:

```json
{
  "username": "alice",
  "salt": "2A7F0B...",
  "verifier": "AE76..."
}
```

Esto sirve para comprender qué se envía y qué no se envía al servidor.

---

## 6. Cómo levantar el proyecto

### Requisitos

- PHP 8.2+
- Composer
- Node.js 18+ para ejecutar la prueba automática
- acceso al navegador

### Instalación de dependencias

Desde la carpeta raíz del proyecto:

```bash
composer install
```

En Windows con XAMPP, si PHP o Composer no están en el `PATH`, usa sus rutas completas. Por ejemplo:

```powershell
& 'C:\xampp\php\php.exe' 'C:\ruta\a\composer.phar' install
```

### Ejecutar la API en local

Desde `C:\Auth Zero trust`:

```bash
php -S 127.0.0.1:8000 -t .
```

En Windows con XAMPP:

```powershell
Set-Location 'C:\Auth Zero trust'
& 'C:\xampp\php\php.exe' -S 127.0.0.1:8000 -t 'C:\Auth Zero trust'
```

Luego abre en el navegador:

```text
http://127.0.0.1:8000/
```

Para detener el servidor, pulsa `Ctrl + C` en la terminal donde está ejecutándose.

### Probar el flujo SRP automáticamente

Con el servidor local activo, abre otra terminal en la raíz del proyecto y ejecuta:

```powershell
node .\test-flow.js
```

La prueba crea un usuario temporal y valida `register`, `challenge` y `verify`. No utiliza contraseñas ni usuarios preconfigurados.

### Ejecutar con Podman

Requiere Podman con su máquina Linux iniciada:

```bash
podman machine start
podman build -f Containerfile -t auth-zero-trust/srp-demo .
podman volume create srp-data
podman run --rm --name srp-demo -p 8080:80 -v srp-data:/var/www/html/data auth-zero-trust/srp-demo
```

Luego abre `http://127.0.0.1:8080/`. El volumen `srp-data` mantiene los usuarios registrados fuera del contenedor.

Como alternativa, si está disponible Compose:

```bash
podman compose -f podman-compose.yml up --build
```

---

## 7. Flujo real del proyecto en una frase

El flujo es este:

1. El cliente calcula una credencial a partir de usuario + contraseña + salt.
2. El servidor guarda solamente el verificador SRP.
3. El cliente genera su valor `A` para iniciar la autenticación.
4. El servidor responde con un desafío `B`.
5. El cliente calcula un secreto compartido sin mandar la contraseña.
6. El cliente envía una prueba `M1`.
7. El servidor recalcula esa prueba y si coincide, autentica al usuario.

---

## 8. Qué hace especial a este prototipo

- Demuestra el patrón Zero-Trust de autenticación sin transmisión directa de contraseña.
- Separación clara entre cliente y servidor.
- El código está hecho para ser fácil de estudiar y modificar.
- Tiene una consola de auditoría para explicar el protocolo paso a paso.

---

## 9. Advertencia importante

Este repositorio es un prototipo funcional para aprendizaje y demostración. No está pensado como sustituir una implementación de autenticación prodcution-ready con:

- validación exhaustiva de grupos criptográficos
- gestión segura de sesiones
- mitigación de ataques de canal lateral
- políticas de rotación de secretos
- registro de eventos, auditoría y hardening de seguridad

---

## 10. Archivos clave del proyecto

- [index.html](index.html): interfaz del usuario y lógica del cliente
- [api.php](api.php): API REST y lógica SRP del servidor
- [db.json](db.json): almacenamiento simulado de usuarios
- [composer.json](composer.json): dependencias del proyecto

Si quieres, en el siguiente paso puedo dejarte también una versión de este README en formato más técnico o más académico, con diagramas de secuencia y una explicación matemática más profunda del cálculo de `x`, `u`, `S` y `M1`.
