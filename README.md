# raypass

Gestor de secretos para la línea de comandos, escrito en [raylang](https://github.com/roberto-ayala/raylang): una bóveda de un solo archivo cifrada entera con ChaCha20-Poly1305 (clave por passphrase vía HKDF, escritura atómica por rename), entrada de passphrase **oculta** (raw mode sin eco), generador de contraseñas CSPRNG, `exec` que inyecta los secretos como variables de entorno del hijo, y **compartir un secreto con una persona** vía sealed box X25519.

```text
$ raypass init
passphrase: ▂
vault created: ~/.raypass.vault

$ raypass add db_url                      # pide el valor oculto
$ raypass gen deploy_token --len 32       # genera, guarda e imprime
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

## Diseño

- **Bóveda**: `{"salt", "nonce", "box"}`; box = AEAD(HKDF(salt, passphrase,
  "raypass-v1"), nonce fresco por guardado, aad="raypass", JSON de entradas).
  Passphrase errónea = fallo de autenticación AEAD, sin más oráculo. Guardado
  por temp + `fs.rename` (una escritura rota jamás corrompe la bóveda).
- **Compartir**: par efímero X25519; clave = HKDF(eph_pub, DH, "raypass-share");
  blob = eph_pub ‖ nonce ‖ box (la regla M114: el DH crudo SIEMPRE pasa por
  HKDF antes de ser clave AEAD). Manipular el blob rompe la autenticación.
- **Entrada oculta**: `term.raw` + lectura byte a byte sin eco, con backspace
  y Ctrl-C; los bytes se decodifican al final (UTF-8 multibyte sobrevive).

## Estado actual

| Capacidad | Estado |
|-----------|--------|
| init/add/get/list/rm/gen con passphrase oculta o por env | ✅ |
| exec con inyección de secretos como env del hijo | ✅ |
| keygen/share/receive (sealed box X25519, tamper-proof) | ✅ |
| Escritura atómica de la bóveda; el cifrado nunca filtra valores (test) | ✅ |
| Binario nativo | ✅ |
| Tests (bóveda, passphrase errónea, share roundtrip + tamper) | ✅ 3 |
| chmod 600 de la bóveda | ❌ bloqueado (fs sin API de permisos) |
| Zeroización de secretos en memoria | ❌ inexpresable (strings GC) |
| Portapapeles con auto-borrado, TOTP | 📋 v2 |

## Hallazgos de dogfod

Anotados en `raylang/IDEAS.md` §71:

1. **La entrada oculta es artesanía sobre raw** (predicho): ~30 líneas que
   toda herramienta de secretos repetirá — candidata directa a
   `term.read_hidden(prompt)`.
2. **Sin chmod**: la bóveda queda con permisos por defecto y no hay forma de
   restringirla (`fs.stat`/`fs.chmod` no existen — la otra cara del hallazgo
   de metadatos de raysync §69).
3. **La zeroización es inexpresable**: los secretos viven en strings del GC
   sin borrado garantizado — decisión de diseño del lenguaje que un gestor de
   secretos hace visible.
4. **Positivo**: la pila M114 completa (X25519 + HKDF + AEAD) compone el
   sealed box en ~40 líneas sin sorpresas, y el mismo patrón temp+rename de
   rayq/raysync vuelve a dar atomicidad gratis.

## Desarrollo

```sh
ray test
ray build --native src/main.ray -o raypass --release
```

Estructura: `src/main.ray` (CLI) · `vault.ray` (bóveda AEAD) · `sharebox.ray`
(X25519) · `input.ray` (entrada oculta).
