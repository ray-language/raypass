# raypass

Gestor de secretos para la línea de comandos, escrito en [raylang](https://github.com/ray-language/raylang): una bóveda de un solo archivo cifrada entera con ChaCha20-Poly1305 (clave por passphrase vía HKDF, escritura atómica por rename), entrada de passphrase **oculta** (raw mode sin eco), generador de contraseñas CSPRNG, `exec` que inyecta los secretos como variables de entorno del hijo, y **compartir un secreto con una persona** vía sealed box X25519.

```text
$ raypass init
passphrase: ▂
vault created: ~/.raypass.vault

$ raypass add db_url                      # pide el valor oculto
$ raypass gen deploy_token --len 32       # genera, guarda e imprime
$ raypass gen                             # solo genera (no abre la bóveda)
$ raypass list
db_url
deploy_token

# El patrón estrella: nada de secretos en texto plano en scripts
$ raypass exec -- ./deploy.sh             # el hijo ve $db_url, $deploy_token

# Compartir con una persona (ella hace `raypass keygen` y te da su public)
$ raypass share db_url --to <public> | pbcopy
# ella:
$ pbpaste | raypass receive --key <secret>
postgres://…
```

`RAYPASS_PASSPHRASE` sirve para scripts/CI (y para los tests).

## Comandos

`raypass [--vault FILE] COMANDO`. La bóveda es `$HOME/.raypass.vault` salvo
`--vault`; los comandos marcados 🔐 piden la passphrase (oculta, o por env).

| Comando | Qué hace |
|---------|----------|
| `init` 🔐 | crea una bóveda vacía (pide la passphrase nueva, 6+ caracteres) |
| `add NAME [VALUE]` 🔐 | guarda un secreto; sin VALUE lo pide oculto. Reemplaza si ya existe |
| `get NAME` 🔐 | imprime el secreto |
| `list` 🔐 | lista los nombres |
| `rm NAME` 🔐 | borra una entrada |
| `gen [NAME] [--len N]` | genera una contraseña (24 caracteres por defecto) y la imprime; con NAME además la guarda 🔐 (reemplaza si ya existe) |
| `exec -- CMD [ARGS...]` 🔐 | ejecuta CMD con cada entrada como variable de entorno; la salida se retransmite y el código de salida es el del hijo |
| `keygen` | par X25519 para compartir: imprime secret y public |
| `share NAME --to PUBKEY` 🔐 | sella un secreto para la public de alguien (sealed box) |
| `receive --key SECKEY` | descifra un blob compartido leído de stdin |

Códigos de salida: 0 ok, 1 error (passphrase errónea, entrada inexistente,
bóveda en uso por otro proceso…); en `exec`, el del hijo.

## Diseño

- **Bóveda**: `{"salt", "nonce", "box"}`; box = AEAD(HKDF(salt, passphrase,
  "raypass-v1"), nonce fresco por guardado, aad="raypass", JSON de entradas).
  Passphrase errónea = fallo de autenticación AEAD, sin más oráculo. Guardado
  por temp + `fs.rename` (una escritura rota jamás corrompe la bóveda).
- **Compartir**: par efímero X25519; clave = HKDF(eph_pub, DH, "raypass-share");
  blob = eph_pub ‖ nonce ‖ box (la regla M114: el DH crudo SIEMPRE pasa por
  HKDF antes de ser clave AEAD). Manipular el blob rompe la autenticación.
- **Entrada oculta**: `term.read_hidden` (M125): prompt a stderr, backspace
  por carácter UTF-8, Ctrl-C = error.
- **Disco** (M115): el temporal se `fsync`ea antes del rename (sobrevive a un
  corte de luz, no solo a un crash), la bóveda queda `chmod 0600` tras cada
  guardado y se avisa al abrirla si alguien la aflojó, y un `.lock` hermano
  (flock) serializa dos `raypass` concurrentes (el segundo falla, no pisa).
- **exec**: la salida del hijo se retransmite en streaming (`process.stream`),
  no al final; el código de salida del hijo es el de raypass.
- **gen**: muestreo por rechazo sobre el alfabeto (sin el sesgo de `byte % n`).

## Estado actual

| Capacidad | Estado |
|-----------|--------|
| init/add/get/list/rm/gen con passphrase oculta o por env | ✅ |
| exec con inyección de secretos como env del hijo | ✅ |
| keygen/share/receive (sealed box X25519, tamper-proof) | ✅ |
| Escritura atómica de la bóveda; el cifrado nunca filtra valores (test) | ✅ |
| Binario nativo | ✅ |
| Tests (bóveda, passphrase errónea, share, alfabeto, permisos, lock) | ✅ 6 |
| chmod 600 de la bóveda + aviso si está más abierta | ✅ (M115.3) |
| fsync antes del rename; lock entre procesos | ✅ (M115.1/.2) |
| Zeroización de secretos en memoria | ❌ inexpresable (strings GC) |
| Portapapeles con auto-borrado, TOTP | 📋 v2 |

## Hallazgos de dogfod

Anotados en `raylang/IDEAS.md` §71:

1. ✅ **La entrada oculta era artesanía sobre raw** (predicho): ~30 líneas que
   toda herramienta de secretos repetía — ejecutado como `term.read_hidden`
   (M125), adoptado aquí.
2. ✅ **Sin chmod**: la bóveda quedaba con permisos por defecto — ejecutado
   como `fs.stat`/`fs.chmod` (M115.3), adoptado aquí junto a `fs.sync` y
   `fs.try_lock` del mismo hito.
3. **La zeroización es inexpresable**: los secretos viven en strings del GC
   sin borrado garantizado — decisión de diseño del lenguaje que un gestor de
   secretos hace visible (documentada en SECURITY.md de raylang).
4. **Positivo**: la pila M114 completa (X25519 + HKDF + AEAD) compone el
   sealed box en ~40 líneas sin sorpresas, y el mismo patrón temp+rename de
   rayq/raysync vuelve a dar atomicidad gratis.
5. **Pendiente: sin KDF de contraseñas** en `std/crypto` (Argon2/PBKDF2). La
   clave se deriva con HKDF, que no es lento: una passphrase débil se ataca
   por fuerza bruta a velocidad de HMAC. Es el siguiente hallazgo a llevar
   a raylang.

## Desarrollo

```sh
ray test
ray build --native src/main.ray -o raypass --release
```

Estructura: `src/main.ray` (CLI) · `vault.ray` (bóveda AEAD, permisos, lock) ·
`sharebox.ray` (X25519) · `input.ray` (entrada oculta).
