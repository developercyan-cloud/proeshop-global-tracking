# ProEshop Global Tracking

Plataforma independiente para gestionar envíos de **ProEshop Logistics**. No utiliza ni modifica la base de datos de ProEshop.

## Comportamiento acordado

- El webhook crea un envío solamente cuando el pedido llega al estado exacto `Enviado`.
- Los eventos webhook se autentican mediante HMAC-SHA256 y una marca de tiempo.
- Los eventos repetidos no duplican envíos (idempotencia por `event_id` y `order_ref`).
- La guía interna se genera con formato `PE-AAAA-XXXXXXXX`.
- El portal público permite consultar por guía o referencia del pedido.
- La consulta pública no expone nombre, correo, teléfono, dirección postal ni datos de pago.
- Las actualizaciones manuales se identifican como **Actualización administrativa**.
- El transportista siempre se muestra como **ProEshop Logistics**. No se simula integración con DHL, FedEx, UPS u otra transportadora.
- El almacenamiento usa SQLite en `TRACKING_DATABASE_PATH`; en Railway se recomienda `/data/tracking.db`.

## Archivos

- `main.py`: aplicación FastAPI y API.
- `templates/`: portal público y panel de administración.
- `static/`: estilos e interacción del portal.
- `Procfile` y `railway.json`: configuración de despliegue.

## Despliegue en Railway (interfaz gráfica)

1. Sube el contenido de esta carpeta al repositorio GitHub `developercyan-cloud/proeshop-global-tracking` (no subas el ZIP dentro del repositorio).
2. En Railway, crea un proyecto nuevo: **New Project → Deploy from GitHub Repo**.
3. Selecciona `proeshop-global-tracking`. No reutilices el servicio ni el volumen de ProEshop.
4. En el servicio nuevo, abre **Volumes** y crea un volumen montado en `/data`.
5. En **Variables**, configura las variables indicadas abajo.
6. En **Settings → Networking**, genera un dominio público.
7. Espera el despliegue y comprueba `https://TU-DOMINIO/health`.

## Variables de Railway

| Variable | Valor |
|---|---|
| `TRACKING_DATABASE_PATH` | `/data/tracking.db` |
| `TRACKING_SESSION_SECRET` | Secreto aleatorio largo, único y privado (mínimo 32 caracteres) |
| `TRACKING_ADMIN_USERNAME` | Usuario de administración que elijas |
| `TRACKING_ADMIN_PASSWORD_HASH` | Hash PBKDF2-SHA256 descrito abajo |
| `TRACKING_SYNC_SECRET` | Secreto aleatorio compartido para autenticar el webhook futuro |

No compartas estos valores en chats ni los guardes en GitHub. No uses las credenciales de ProEshop.

### Formato de contraseña

`TRACKING_ADMIN_PASSWORD_HASH` debe tener este formato:

`pbkdf2_sha256$310000$SAL_HEX$HASH_HEX`

El salt debe ser aleatorio y el hash debe ser PBKDF2-HMAC-SHA256 con al menos 310.000 iteraciones. Usa un gestor de contraseñas o una herramienta segura local para generarlo. No introduzcas la contraseña en esta conversación.

## Webhook futuro desde ProEshop

**La integración no queda activa por desplegar este repositorio.** Más adelante habrá que configurar el backend de ProEshop para enviar el evento cuando un pedido cambie a `Enviado`. Ese cambio en ProEshop no está incluido aquí.

- Método: `POST`
- Ruta: `/api/integrations/proeshop/orders`
- Encabezado `X-ProEshop-Timestamp`: timestamp Unix en segundos.
- Encabezado `X-ProEshop-Signature`: HMAC-SHA256 hexadecimal de `timestamp + "." + cuerpo_HTTP_sin_modificar`, usando `TRACKING_SYNC_SECRET`.

Ejemplo de cuerpo:

```json
{
  "event_id": "evt-unique-001",
  "order_ref": "PS-100045",
  "status": "Enviado",
  "origin_city": "Bogotá",
  "origin_country": "Colombia",
  "destination_city": "Medellín",
  "destination_country": "Colombia",
  "package_description": "Paquete ProEshop",
  "estimated_delivery": "2026-12-02"
}
```

No envíes datos personales del comprador. Si `status` no es exactamente `Enviado` (ignorando mayúsculas/minúsculas y espacios exteriores), no se crea ningún envío.

## Prueba inicial

- `GET /health`: estado de la aplicación.
- `GET /`: portal público.
- `GET /admin`: acceso al panel.
- `GET /api/tracking/lookup?q=...`: consulta pública.

El panel y el webhook permanecen deshabilitados si faltan sus secretos de configuración. La limitación de intentos del panel y de consultas se mantiene en memoria por instancia; para despliegues con varias réplicas se recomienda añadir un limitador compartido externo.
