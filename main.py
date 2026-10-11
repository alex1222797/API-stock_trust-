"""API principal de StockTrust.

Registra empresas junto con su primer administrador y autentica a los
usuarios de la aplicación de escritorio mediante tokens JWT.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import html
import logging
import os
import re
import secrets
import string
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
import mysql.connector
import requests
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from mysql.connector import Error, IntegrityError
from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    field_validator,
    model_validator,
)


# =============================================================================
# CONFIGURACION
# =============================================================================

load_dotenv()

logger = logging.getLogger("stocktrust.api")
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)

DB_CONFIG = {
    "host": os.getenv("MYSQL_HOST", "localhost"),
    "port": int(os.getenv("MYSQL_PORT", "3306")),
    "user": os.getenv("MYSQL_USER", "root"),
    "password": os.getenv("MYSQL_PASSWORD", ""),
    "database": os.getenv("MYSQL_DATABASE", "stock_trust"),
    "charset": "utf8mb4",
    "connection_timeout": int(os.getenv("MYSQL_CONNECT_TIMEOUT", "15")),
}

mysql_ssl_ca = os.getenv("MYSQL_SSL_CA", "").strip()
if mysql_ssl_ca:
    DB_CONFIG.update({"ssl_ca": mysql_ssl_ca, "ssl_verify_cert": True})

BREVO_CONFIG = {
    "url": "https://api.brevo.com/v3/smtp/email",
    "api_key": os.getenv("BREVO_API_KEY", "").strip(),
    "sender_email": os.getenv("BREVO_SENDER_EMAIL", "").strip(),
    "sender_name": os.getenv("BREVO_SENDER_NAME", "StockTrust").strip(),
    "timeout": int(os.getenv("BREVO_TIMEOUT", "20")),
}

JWT_SECRET = os.getenv("JWT_SECRET", "").strip()
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "480"))


# =============================================================================
# BASE DE DATOS Y SEGURIDAD
# =============================================================================

def obtener_conexion():
    return mysql.connector.connect(**DB_CONFIG)


def generar_hash_contrasena(contrasena: str) -> str:
    iteraciones = 310_000
    sal = secrets.token_urlsafe(16)
    resumen = hashlib.pbkdf2_hmac(
        "sha256",
        contrasena.encode("utf-8"),
        sal.encode("utf-8"),
        iteraciones,
    ).hex()
    return f"pbkdf2_sha256${iteraciones}${sal}${resumen}"


def verificar_hash_contrasena(contrasena: str, hash_guardado: str) -> bool:
    try:
        algoritmo, iteraciones, sal, resumen_guardado = hash_guardado.split("$", 3)
        if algoritmo != "pbkdf2_sha256":
            return False

        resumen_calculado = hashlib.pbkdf2_hmac(
            "sha256",
            contrasena.encode("utf-8"),
            sal.encode("utf-8"),
            int(iteraciones),
        ).hex()
        return hmac.compare_digest(resumen_calculado, resumen_guardado)
    except (AttributeError, TypeError, ValueError):
        return False


def generar_token_acceso(usuario: dict) -> str:
    if not JWT_SECRET:
        raise RuntimeError("JWT_SECRET no esta configurada.")

    ahora = datetime.now(timezone.utc)
    contenido = {
        "sub": str(usuario["id_usuario"]),
        "id_empresa": int(usuario["id_empresa"]),
        "rol": str(usuario["rol"]),
        "iat": ahora,
        "exp": ahora + timedelta(minutes=JWT_EXPIRE_MINUTES),
    }
    return jwt.encode(contenido, JWT_SECRET, algorithm=JWT_ALGORITHM)


seguridad_http = HTTPBearer(auto_error=False)


def obtener_sesion_actual(
    credenciales: HTTPAuthorizationCredentials | None = Depends(seguridad_http),
) -> dict:
    if credenciales is None or credenciales.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Debes iniciar sesion.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not JWT_SECRET:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="La autenticacion no esta configurada.",
        )

    try:
        contenido = jwt.decode(
            credenciales.credentials,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
        )
        return {
            "id_usuario": int(contenido["sub"]),
            "id_empresa": int(contenido["id_empresa"]),
            "rol": str(contenido["rol"]),
        }
    except jwt.ExpiredSignatureError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="La sesion vencio. Inicia sesion nuevamente.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from error
    except (jwt.InvalidTokenError, KeyError, TypeError, ValueError) as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="La sesion no es valida.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from error


def requerir_administrador(
    sesion: dict = Depends(obtener_sesion_actual),
) -> dict:
    if str(sesion.get("rol", "")).lower() != "administrador":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Esta operacion requiere una cuenta administradora.",
        )
    return sesion


def preparar_esquema_usuarios() -> None:
    """Ajusta únicamente la columna de fotografía para admitir imágenes pequeñas."""
    conexion = None
    cursor = None
    try:
        conexion = obtener_conexion()
        cursor = conexion.cursor(dictionary=True)
        cursor.execute("SHOW COLUMNS FROM usuarios LIKE 'foto'")
        columna = cursor.fetchone()
        if columna is not None and "text" not in str(columna.get("Type", "")).lower():
            cursor.execute("ALTER TABLE usuarios MODIFY foto MEDIUMTEXT NULL")
            conexion.commit()
            logger.info("Columna usuarios.foto preparada para imagenes remotas.")
    finally:
        if cursor is not None:
            cursor.close()
        if conexion is not None and conexion.is_connected():
            conexion.close()
# =============================================================================
# NORMALIZACION Y VALIDACION
# =============================================================================

def limpiar_espacios(valor: str) -> str:
    return " ".join(valor.strip().split())


def limpiar_documento(valor: str) -> str:
    return re.sub(r"\D", "", valor)


PATRON_TELEFONO_SV = re.compile(r"^(?:\+503[\s-]?)?[267]\d{3}-?\d{4}$")
PATRON_DUI = re.compile(r"^\d{8}-\d$")


def validar_foto_data_uri(valor: Optional[str]) -> Optional[str]:
    if not valor:
        return None
    coincidencia = re.fullmatch(
        r"data:image/(jpeg|png|webp);base64,([A-Za-z0-9+/=]+)",
        valor,
    )
    if coincidencia is None:
        raise ValueError("La fotografia no tiene un formato valido.")
    try:
        contenido = base64.b64decode(coincidencia.group(2), validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError("La fotografia no contiene datos validos.") from error
    if len(contenido) > 900_000:
        raise ValueError("La fotografia no debe superar 900 KB.")
    return valor


# =============================================================================
# MODELOS
# =============================================================================

class DatosEmpresa(BaseModel):
    model_config = ConfigDict(extra="forbid")

    nombre_comercial: str = Field(min_length=2, max_length=120)
    razon_social: str = Field(min_length=2, max_length=150)
    nit: str = Field(min_length=9, max_length=20)
    actividad_economica: str = Field(min_length=2, max_length=150)
    correo: EmailStr
    telefono: str = Field(min_length=8, max_length=20)
    direccion: str = Field(min_length=10, max_length=255)

    @field_validator(
        "nombre_comercial",
        "razon_social",
        "actividad_economica",
        "direccion",
        mode="before",
    )
    @classmethod
    def normalizar_textos(cls, valor):
        return limpiar_espacios(valor) if isinstance(valor, str) else valor

    @field_validator("nit")
    @classmethod
    def validar_nit(cls, valor: str):
        nit = limpiar_documento(valor)
        if len(nit) not in (9, 14):
            raise ValueError("El NIT debe contener 9 o 14 digitos.")
        return nit

    @field_validator("telefono")
    @classmethod
    def validar_telefono(cls, valor: str):
        telefono = valor.strip()
        if not PATRON_TELEFONO_SV.fullmatch(telefono):
            raise ValueError("Ingresa un telefono salvadoreno valido.")
        return telefono


class DatosAdministrador(BaseModel):
    model_config = ConfigDict(extra="forbid")

    nombre: str = Field(min_length=2, max_length=60)
    apellido: str = Field(min_length=2, max_length=60)
    dui: str = Field(min_length=10, max_length=10)
    correo: EmailStr
    telefono: str = Field(min_length=8, max_length=20)
    direccion: str = Field(min_length=10, max_length=255)
    contrasena: str = Field(min_length=10, max_length=72)
    confirmar_contrasena: str = Field(min_length=10, max_length=72)

    @field_validator("nombre", "apellido", "direccion", mode="before")
    @classmethod
    def normalizar_textos(cls, valor):
        return limpiar_espacios(valor) if isinstance(valor, str) else valor

    @field_validator("dui")
    @classmethod
    def validar_dui(cls, valor: str):
        dui = valor.strip()
        if not PATRON_DUI.fullmatch(dui):
            raise ValueError("El DUI debe tener el formato 00000000-0.")
        return dui

    @field_validator("telefono")
    @classmethod
    def validar_telefono(cls, valor: str):
        telefono = valor.strip()
        if not PATRON_TELEFONO_SV.fullmatch(telefono):
            raise ValueError("Ingresa un telefono salvadoreno valido.")
        return telefono

    @field_validator("contrasena")
    @classmethod
    def validar_seguridad_contrasena(cls, valor: str):
        errores = []
        if not re.search(r"[A-Z]", valor):
            errores.append("una letra mayuscula")
        if not re.search(r"[a-z]", valor):
            errores.append("una letra minuscula")
        if not re.search(r"\d", valor):
            errores.append("un numero")
        if not re.search(r"[^A-Za-z0-9]", valor):
            errores.append("un caracter especial")
        if errores:
            raise ValueError("La contrasena debe incluir " + ", ".join(errores) + ".")
        return valor

    @model_validator(mode="after")
    def comprobar_contrasenas(self):
        if self.contrasena != self.confirmar_contrasena:
            raise ValueError("Las contrasenas no coinciden.")
        return self


class RegistroEmpresa(BaseModel):
    model_config = ConfigDict(extra="forbid")

    empresa: DatosEmpresa
    administrador: DatosAdministrador
    acepta_terminos: bool

    @field_validator("acepta_terminos")
    @classmethod
    def comprobar_terminos(cls, valor: bool):
        if valor is not True:
            raise ValueError("Debes aceptar los terminos y condiciones.")
        return valor


class RespuestaRegistro(BaseModel):
    exito: bool
    mensaje: str
    codigo_empresa: str
    id_empresa: int
    id_administrador: int
    usuario: str
    correo_enviado: bool
    correo_destino: EmailStr
    aviso: Optional[str] = None


class CredencialesLogin(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dui: str = Field(min_length=10, max_length=10)
    contrasena: str = Field(min_length=1, max_length=72)

    @field_validator("dui")
    @classmethod
    def validar_dui(cls, valor: str):
        dui = valor.strip()
        if not PATRON_DUI.fullmatch(dui):
            raise ValueError("El DUI debe tener el formato 00000000-0.")
        return dui


class DatosEmpleado(BaseModel):
    model_config = ConfigDict(extra="forbid")

    nombre: str = Field(min_length=2, max_length=60)
    apellido: str = Field(min_length=2, max_length=60)
    dui: str = Field(min_length=10, max_length=10)
    correo: EmailStr
    telefono: str = Field(min_length=8, max_length=20)
    direccion: str = Field(min_length=5, max_length=255)
    contrasena_temporal: str = Field(min_length=10, max_length=72)
    foto: Optional[str] = Field(default=None, max_length=1_500_000)

    @field_validator("nombre", "apellido", "direccion", mode="before")
    @classmethod
    def normalizar_textos(cls, valor):
        return limpiar_espacios(valor) if isinstance(valor, str) else valor

    @field_validator("dui")
    @classmethod
    def validar_dui(cls, valor: str):
        dui = valor.strip()
        if not PATRON_DUI.fullmatch(dui):
            raise ValueError("El DUI debe tener el formato 00000000-0.")
        return dui

    @field_validator("telefono")
    @classmethod
    def validar_telefono(cls, valor: str):
        telefono = valor.strip()
        if not PATRON_TELEFONO_SV.fullmatch(telefono):
            raise ValueError("Ingresa un telefono salvadoreno valido.")
        return telefono

    @field_validator("foto")
    @classmethod
    def validar_foto(cls, valor: Optional[str]):
        return validar_foto_data_uri(valor)


class ActualizarEmpleado(BaseModel):
    model_config = ConfigDict(extra="forbid")

    nombre: str = Field(min_length=2, max_length=60)
    apellido: str = Field(min_length=2, max_length=60)
    dui: str = Field(min_length=10, max_length=10)
    correo: EmailStr
    telefono: str = Field(min_length=8, max_length=20)
    direccion: str = Field(min_length=5, max_length=255)
    estado: str
    foto: Optional[str] = Field(default=None, max_length=1_500_000)

    @field_validator("nombre", "apellido", "direccion", mode="before")
    @classmethod
    def normalizar_textos(cls, valor):
        return limpiar_espacios(valor) if isinstance(valor, str) else valor

    @field_validator("dui")
    @classmethod
    def validar_dui(cls, valor: str):
        dui = valor.strip()
        if not PATRON_DUI.fullmatch(dui):
            raise ValueError("El DUI debe tener el formato 00000000-0.")
        return dui

    @field_validator("telefono")
    @classmethod
    def validar_telefono(cls, valor: str):
        telefono = valor.strip()
        if not PATRON_TELEFONO_SV.fullmatch(telefono):
            raise ValueError("Ingresa un telefono salvadoreno valido.")
        return telefono

    @field_validator("estado")
    @classmethod
    def validar_estado(cls, valor: str):
        estado_usuario = valor.strip().lower()
        if estado_usuario not in {"activo", "inactivo"}:
            raise ValueError("El estado debe ser activo o inactivo.")
        return estado_usuario

    @field_validator("foto")
    @classmethod
    def validar_foto(cls, valor: Optional[str]):
        return validar_foto_data_uri(valor)


class CambioEstadoUsuario(BaseModel):
    model_config = ConfigDict(extra="forbid")
    estado: str

    @field_validator("estado")
    @classmethod
    def validar_estado(cls, valor: str):
        estado_usuario = valor.strip().lower()
        if estado_usuario not in {"activo", "inactivo"}:
            raise ValueError("El estado debe ser activo o inactivo.")
        return estado_usuario


# =============================================================================
# CORREO
# =============================================================================

def enviar_correo_bienvenida(
    destinatario: str,
    nombre_administrador: str,
    nombre_empresa: str,
    codigo_empresa: str,
    usuario: str,
) -> tuple[bool, Optional[str]]:
    if not BREVO_CONFIG["api_key"]:
        aviso = "La cuenta se creo, pero la API de correo no esta configurada."
        logger.warning(aviso)
        return False, aviso

    if not BREVO_CONFIG["sender_email"]:
        aviso = "La cuenta se creo, pero falta configurar el correo remitente."
        logger.warning(aviso)
        return False, aviso

    nombre_seguro = html.escape(nombre_administrador)
    empresa_segura = html.escape(nombre_empresa)
    codigo_seguro = html.escape(codigo_empresa)
    usuario_seguro = html.escape(usuario)

    contenido_texto = f"""Hola, {nombre_administrador}.

La empresa {nombre_empresa} fue registrada correctamente en StockTrust.

Codigo de empresa: {codigo_empresa}
Usuario administrador: {usuario}

Utiliza la contrasena que creaste durante el registro. Por seguridad, nunca
enviamos ni mostramos tu contrasena por correo.

Sitio oficial: https://stocktrustinfo.netlify.app/
"""

    contenido_html = f"""<!doctype html>
<html lang="es">
<body style="margin:0;background:#eef3f7;font-family:Arial,sans-serif;color:#112b45">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
    <tr><td align="center" style="padding:32px 16px">
      <table role="presentation" width="600" cellspacing="0" cellpadding="0"
             style="max-width:600px;width:100%;background:#fff;border-radius:18px;overflow:hidden">
        <tr><td style="background:#112b45;padding:28px 34px;color:#fff">
          <h1 style="margin:0;font-size:28px">StockTrust</h1>
          <p style="margin:6px 0 0;color:#d8e7f5">Organiza. Controla. Haz crecer.</p>
        </td></tr>
        <tr><td style="padding:34px">
          <h2 style="margin:0 0 14px">Bienvenido, {nombre_seguro}</h2>
          <p style="line-height:1.7">La empresa <strong>{empresa_segura}</strong>
             fue registrada correctamente.</p>
          <div style="border-left:4px solid #ee6c2b;background:#f4f7fa;padding:18px;margin:24px 0">
            <p style="margin:0 0 8px"><strong>Codigo:</strong> {codigo_seguro}</p>
            <p style="margin:0"><strong>Usuario:</strong> {usuario_seguro}</p>
          </div>
          <p style="line-height:1.7">Ingresa con la contrasena que creaste en
             el formulario. Por seguridad no se envia por correo.</p>
          <p style="margin-top:28px">
            <a href="https://stocktrustinfo.netlify.app/"
               style="display:inline-block;background:#ee6c2b;color:#fff;text-decoration:none;padding:13px 22px;border-radius:9px;font-weight:bold">
              Visitar StockTrust
            </a>
          </p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""

    encabezados = {
        "accept": "application/json",
        "api-key": BREVO_CONFIG["api_key"],
        "content-type": "application/json",
    }

    datos_correo = {
        "sender": {
            "name": BREVO_CONFIG["sender_name"],
            "email": BREVO_CONFIG["sender_email"],
        },
        "to": [
            {
                "email": destinatario,
                "name": nombre_administrador,
            }
        ],
        "replyTo": {
            "email": BREVO_CONFIG["sender_email"],
            "name": BREVO_CONFIG["sender_name"],
        },
        "subject": "Bienvenido a StockTrust",
        "textContent": contenido_texto,
        "htmlContent": contenido_html,
    }

    try:
        respuesta = requests.post(
            BREVO_CONFIG["url"],
            headers=encabezados,
            json=datos_correo,
            timeout=BREVO_CONFIG["timeout"],
        )

        if 200 <= respuesta.status_code < 300:
            logger.info(
                "Correo de bienvenida enviado correctamente a %s.",
                destinatario,
            )
            return True, None

        logger.error(
            "Brevo rechazo el correo. Codigo %s: %s",
            respuesta.status_code,
            respuesta.text[:500],
        )
        return (
            False,
            "La cuenta se creo, pero el servicio de correo rechazo el envio.",
        )
    except requests.Timeout:
        logger.exception("Brevo tardo demasiado en responder.")
        return (
            False,
            "La cuenta se creo, pero el correo tardo demasiado en enviarse.",
        )
    except requests.RequestException as error:
        logger.exception("No se pudo conectar con la API de Brevo: %s", error)
        return (
            False,
            "La cuenta se creo, pero no se pudo conectar con el correo.",
        )


def enviar_correo_credenciales_empleado(
    destinatario: str,
    nombre: str,
    empresa: str,
    dui: str,
    contrasena_temporal: str,
    fecha_expiracion: datetime,
) -> tuple[bool, Optional[str]]:
    if not BREVO_CONFIG["api_key"] or not BREVO_CONFIG["sender_email"]:
        return False, "El servicio de correo no esta configurado."

    vencimiento = fecha_expiracion.strftime("%d/%m/%Y a las %I:%M %p")
    nombre_seguro = html.escape(nombre)
    empresa_segura = html.escape(empresa)
    dui_seguro = html.escape(dui)
    clave_segura = html.escape(contrasena_temporal)
    vencimiento_seguro = html.escape(vencimiento)

    texto = f"""Hola, {nombre}.

Se creo tu cuenta de empleado para {empresa} en StockTrust.

Usuario (DUI): {dui}
Contrasena temporal: {contrasena_temporal}
Vencimiento: {vencimiento}

Al iniciar sesion deberas crear una contrasena personal.
No compartas estas credenciales.
"""

    contenido_html = f"""<!doctype html>
<html lang="es">
<body style="margin:0;background:#eef3f7;font-family:Arial,sans-serif;color:#112b45">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
    <tr><td align="center" style="padding:32px 16px">
      <table role="presentation" width="600" cellspacing="0" cellpadding="0"
             style="max-width:600px;width:100%;background:#fff;border-radius:18px;overflow:hidden">
        <tr><td style="background:#112b45;padding:28px 34px;color:#fff">
          <h1 style="margin:0;font-size:28px">StockTrust</h1>
          <p style="margin:6px 0 0;color:#d8e7f5">Tu cuenta de empleado esta lista.</p>
        </td></tr>
        <tr><td style="padding:34px">
          <h2 style="margin:0 0 14px">Hola, {nombre_seguro}</h2>
          <p style="line-height:1.7">Se creo tu acceso para <strong>{empresa_segura}</strong>.</p>
          <div style="border-left:4px solid #ee6c2b;background:#f4f7fa;padding:18px;margin:24px 0">
            <p style="margin:0 0 9px"><strong>Usuario:</strong> {dui_seguro}</p>
            <p style="margin:0 0 9px"><strong>Contrasena temporal:</strong> {clave_segura}</p>
            <p style="margin:0"><strong>Vence:</strong> {vencimiento_seguro}</p>
          </div>
          <p style="line-height:1.7">Al iniciar sesion deberas reemplazarla por una contrasena personal.</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""

    try:
        respuesta = requests.post(
            BREVO_CONFIG["url"],
            headers={
                "accept": "application/json",
                "api-key": BREVO_CONFIG["api_key"],
                "content-type": "application/json",
            },
            json={
                "sender": {
                    "name": BREVO_CONFIG["sender_name"],
                    "email": BREVO_CONFIG["sender_email"],
                },
                "to": [{"email": destinatario, "name": nombre}],
                "subject": "Tus credenciales temporales de StockTrust",
                "textContent": texto,
                "htmlContent": contenido_html,
            },
            timeout=BREVO_CONFIG["timeout"],
        )
        if 200 <= respuesta.status_code < 300:
            return True, None
        logger.error(
            "Brevo rechazo las credenciales del empleado. Codigo %s: %s",
            respuesta.status_code,
            respuesta.text[:500],
        )
        return False, "Brevo rechazo el envio de las credenciales."
    except requests.RequestException as error:
        logger.exception("No se pudieron enviar las credenciales: %s", error)
        return False, "No fue posible conectar con el servicio de correo."


def generar_codigo_empresa(cursor) -> str:
    caracteres = string.ascii_uppercase + string.digits
    anio_actual = datetime.now().year

    for _ in range(10):
        sufijo = "".join(secrets.choice(caracteres) for _ in range(6))
        codigo = f"ST-{anio_actual}-{sufijo}"
        cursor.execute(
            "SELECT id_empresa FROM empresas WHERE codigo_empresa = %s LIMIT 1",
            (codigo,),
        )
        if cursor.fetchone() is None:
            return codigo

    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="No se pudo generar el codigo de la empresa.",
    )


# =============================================================================
# APLICACION
# =============================================================================

@asynccontextmanager
async def lifespan(_app: FastAPI):
    conexion = None
    try:
        conexion = obtener_conexion()
        logger.info("StockTrust API conectada correctamente con MySQL.")
    except Error as error:
        logger.error("No se pudo conectar con MySQL: %s", error)
    finally:
        if conexion is not None and conexion.is_connected():
            conexion.close()

    try:
        preparar_esquema_usuarios()
    except Error as error:
        logger.error("No se pudo preparar la tabla usuarios: %s", error)

    if not JWT_SECRET:
        logger.warning("JWT_SECRET no esta configurada; el login no emitira tokens.")
    yield


app = FastAPI(
    title="StockTrust API",
    description="API de registro y autenticacion para StockTrust.",
    version="1.3.0",
    lifespan=lifespan,
)

origenes_permitidos = [
    "http://127.0.0.1:5500",
    "http://localhost:5500",
    "http://127.0.0.1:8000",
    "http://localhost:8000",
    "https://stocktrustin.netlify.app",
    "https://stocktrustinfo.netlify.app",
]

for variable in ("FRONTEND_URL", "NETLIFY_URL"):
    origen = os.getenv(variable, "").strip().rstrip("/")
    if origen:
        origenes_permitidos.append(origen)

app.add_middleware(
    CORSMiddleware,
    allow_origins=sorted(set(origenes_permitidos)),
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)


# =============================================================================
# ENDPOINTS GENERALES Y AUTENTICACION
# =============================================================================

@app.get("/")
def inicio():
    return {
        "aplicacion": "StockTrust API",
        "version": "1.3.0",
        "documentacion": "/docs",
    }


@app.get("/api/salud")
def comprobar_salud():
    conexion = None
    cursor = None
    try:
        conexion = obtener_conexion()
        cursor = conexion.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        return {
            "estado": "correcto",
            "api": "StockTrust API",
            "base_datos": "conectada",
        }
    except Error as error:
        logger.error("Error de conexion: %s", error)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="La API funciona, pero MySQL no esta disponible.",
        ) from error
    finally:
        if cursor is not None:
            cursor.close()
        if conexion is not None and conexion.is_connected():
            conexion.close()


@app.post("/api/auth/login")
def iniciar_sesion(datos: CredencialesLogin):
    conexion = None
    cursor = None
    try:
        conexion = obtener_conexion()
        cursor = conexion.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT
                u.id_usuario,
                u.id_empresa,
                u.nombre,
                u.apellido,
                u.dui,
                u.correo,
                u.nombre_usuario,
                u.contrasena_hash,
                u.rol,
                u.estado,
                u.debe_cambiar_contrasena,
                u.fecha_expiracion_temporal,
                e.nombre_comercial AS empresa,
                e.estado AS estado_empresa
            FROM usuarios AS u
            INNER JOIN empresas AS e ON e.id_empresa = u.id_empresa
            WHERE u.dui = %s OR u.nombre_usuario = %s
            LIMIT 1
            """,
            (datos.dui, datos.dui),
        )
        usuario = cursor.fetchone()

        if usuario is None or not verificar_hash_contrasena(
            datos.contrasena, usuario["contrasena_hash"]
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="El DUI o la contrasena son incorrectos.",
            )

        if str(usuario["estado"]).lower() != "activo":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="La cuenta se encuentra inactiva.",
            )
        if str(usuario["estado_empresa"]).lower() != "activa":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="La empresa se encuentra inactiva.",
            )

        expiracion = usuario.get("fecha_expiracion_temporal")
        if (
            bool(usuario.get("debe_cambiar_contrasena"))
            and expiracion is not None
            and datetime.now() > expiracion
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="La contrasena temporal ha vencido.",
            )

        token = generar_token_acceso(usuario)
        return {
            "mensaje": "Inicio de sesion correcto.",
            "access_token": token,
            "token_type": "bearer",
            "usuario": {
                "id_usuario": usuario["id_usuario"],
                "id_empresa": usuario["id_empresa"],
                "nombre": usuario["nombre"],
                "apellido": usuario["apellido"],
                "dui": usuario["dui"],
                "correo": usuario["correo"],
                "nombre_usuario": usuario["nombre_usuario"],
                "rol": usuario["rol"],
                "estado": usuario["estado"],
                "empresa": usuario["empresa"],
                "debe_cambiar_contrasena": bool(
                    usuario["debe_cambiar_contrasena"]
                ),
                "fecha_expiracion_temporal": (
                    expiracion.isoformat() if expiracion else None
                ),
            },
        }
    except HTTPException:
        raise
    except RuntimeError as error:
        logger.exception("Configuracion de autenticacion incompleta")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="La autenticacion no esta configurada correctamente.",
        ) from error
    except Error as error:
        logger.exception("Error de MySQL durante el inicio de sesion")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No fue posible consultar las credenciales.",
        ) from error
    finally:
        if cursor is not None:
            cursor.close()
        if conexion is not None and conexion.is_connected():
            conexion.close()


@app.get("/api/auth/me")
def consultar_sesion(sesion: dict = Depends(obtener_sesion_actual)):
    conexion = None
    cursor = None
    try:
        conexion = obtener_conexion()
        cursor = conexion.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT
                u.id_usuario,
                u.id_empresa,
                u.nombre,
                u.apellido,
                u.dui,
                u.correo,
                u.nombre_usuario,
                u.rol,
                u.estado,
                e.nombre_comercial AS empresa
            FROM usuarios AS u
            INNER JOIN empresas AS e ON e.id_empresa = u.id_empresa
            WHERE u.id_usuario = %s AND u.id_empresa = %s
            LIMIT 1
            """,
            (sesion["id_usuario"], sesion["id_empresa"]),
        )
        usuario = cursor.fetchone()
        if usuario is None or str(usuario["estado"]).lower() != "activo":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="La cuenta ya no esta disponible.",
            )
        return {"usuario": usuario}
    except HTTPException:
        raise
    except Error as error:
        logger.exception("No se pudo consultar la sesion")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No fue posible consultar la sesion.",
        ) from error
    finally:
        if cursor is not None:
            cursor.close()
        if conexion is not None and conexion.is_connected():
            conexion.close()


# =============================================================================
# ADMINISTRACION DE EMPLEADOS
# =============================================================================

@app.get("/api/admin/resumen")
def consultar_resumen_admin(
    sesion: dict = Depends(requerir_administrador),
):
    conexion = cursor = None
    try:
        conexion = obtener_conexion()
        cursor = conexion.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT
                COUNT(*) AS total,
                COALESCE(SUM(rol = 'empleado' AND estado = 'activo'), 0) AS empleados,
                COALESCE(SUM(rol = 'administrador'), 0) AS administradores,
                COALESCE(SUM(debe_cambiar_contrasena = 1), 0) AS pendientes
            FROM usuarios
            WHERE id_empresa = %s
            """,
            (sesion["id_empresa"],),
        )
        resumen = cursor.fetchone() or {}
        cursor.execute(
            """
            SELECT id_usuario, nombre, apellido, dui, rol, estado, fecha_creacion
            FROM usuarios
            WHERE id_empresa = %s
            ORDER BY id_usuario DESC
            LIMIT 7
            """,
            (sesion["id_empresa"],),
        )
        recientes = cursor.fetchall()
        for usuario in recientes:
            fecha = usuario.get("fecha_creacion")
            usuario["fecha_creacion"] = fecha.isoformat() if fecha else None
        return {
            "resumen": {clave: int(valor or 0) for clave, valor in resumen.items()},
            "recientes": recientes,
        }
    except Error as error:
        logger.exception("No se pudo cargar el resumen administrativo")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No fue posible cargar el resumen administrativo.",
        ) from error
    finally:
        if cursor is not None:
            cursor.close()
        if conexion is not None and conexion.is_connected():
            conexion.close()


@app.get("/api/usuarios")
def listar_usuarios(
    q: str = "",
    sesion: dict = Depends(requerir_administrador),
):
    conexion = cursor = None
    try:
        termino = f"%{q.strip()}%"
        conexion = obtener_conexion()
        cursor = conexion.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT id_usuario, nombre, apellido, dui, correo, rol, estado,
                   debe_cambiar_contrasena, fecha_creacion
            FROM usuarios
            WHERE id_empresa = %s
              AND rol = 'empleado'
              AND (
                    CONCAT(nombre, ' ', apellido) LIKE %s
                    OR dui LIKE %s
                    OR correo LIKE %s
                  )
            ORDER BY nombre, apellido
            """,
            (sesion["id_empresa"], termino, termino, termino),
        )
        usuarios = cursor.fetchall()
        for usuario in usuarios:
            fecha = usuario.get("fecha_creacion")
            usuario["fecha_creacion"] = fecha.isoformat() if fecha else None
            usuario["debe_cambiar_contrasena"] = bool(
                usuario.get("debe_cambiar_contrasena")
            )
        return {"usuarios": usuarios}
    except Error as error:
        logger.exception("No se pudieron listar los usuarios")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No fue posible cargar los usuarios.",
        ) from error
    finally:
        if cursor is not None:
            cursor.close()
        if conexion is not None and conexion.is_connected():
            conexion.close()


@app.get("/api/usuarios/{id_usuario}")
def consultar_usuario(
    id_usuario: int,
    sesion: dict = Depends(requerir_administrador),
):
    conexion = cursor = None
    try:
        conexion = obtener_conexion()
        cursor = conexion.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT id_usuario, nombre, apellido, dui, correo, direccion, foto,
                   nombre_usuario, rol, telefono, estado,
                   debe_cambiar_contrasena, fecha_expiracion_temporal,
                   fecha_creacion, contrasena_actualizada_en
            FROM usuarios
            WHERE id_usuario = %s AND id_empresa = %s
            LIMIT 1
            """,
            (id_usuario, sesion["id_empresa"]),
        )
        usuario = cursor.fetchone()
        if usuario is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="El usuario no existe dentro de tu empresa.",
            )
        for campo in (
            "fecha_expiracion_temporal",
            "fecha_creacion",
            "contrasena_actualizada_en",
        ):
            fecha = usuario.get(campo)
            usuario[campo] = fecha.isoformat() if fecha else None
        usuario["debe_cambiar_contrasena"] = bool(
            usuario.get("debe_cambiar_contrasena")
        )
        return {"usuario": usuario}
    except HTTPException:
        raise
    except Error as error:
        logger.exception("No se pudo consultar el usuario")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No fue posible consultar el usuario.",
        ) from error
    finally:
        if cursor is not None:
            cursor.close()
        if conexion is not None and conexion.is_connected():
            conexion.close()


@app.post("/api/usuarios", status_code=status.HTTP_201_CREATED)
def crear_empleado(
    datos: DatosEmpleado,
    sesion: dict = Depends(requerir_administrador),
):
    conexion = cursor = None
    try:
        conexion = obtener_conexion()
        conexion.autocommit = False
        cursor = conexion.cursor(dictionary=True)
        conexion.start_transaction()

        correo = str(datos.correo).lower()
        cursor.execute(
            """
            SELECT id_usuario
            FROM usuarios
            WHERE dui = %s OR correo = %s OR nombre_usuario = %s
            LIMIT 1
            """,
            (datos.dui, correo, datos.dui),
        )
        if cursor.fetchone() is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="El DUI o correo ya se encuentra registrado.",
            )

        cursor.execute(
            "SELECT nombre_comercial FROM empresas WHERE id_empresa = %s LIMIT 1",
            (sesion["id_empresa"],),
        )
        empresa = cursor.fetchone()
        if empresa is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No se encontro la empresa de la sesion.",
            )

        expiracion = datetime.now() + timedelta(hours=24)
        cursor.execute(
            """
            INSERT INTO usuarios (
                id_empresa, nombre, apellido, dui, correo, telefono, direccion,
                foto, nombre_usuario, contrasena_hash, rol, estado,
                debe_cambiar_contrasena, fecha_expiracion_temporal
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                'empleado', 'activo', TRUE, %s
            )
            """,
            (
                sesion["id_empresa"],
                datos.nombre,
                datos.apellido,
                datos.dui,
                correo,
                datos.telefono,
                datos.direccion,
                datos.foto,
                datos.dui,
                generar_hash_contrasena(datos.contrasena_temporal),
                expiracion,
            ),
        )
        id_usuario = cursor.lastrowid

        enviado, aviso = enviar_correo_credenciales_empleado(
            destinatario=correo,
            nombre=datos.nombre,
            empresa=empresa["nombre_comercial"],
            dui=datos.dui,
            contrasena_temporal=datos.contrasena_temporal,
            fecha_expiracion=expiracion,
        )
        if not enviado:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=aviso or "No se pudieron enviar las credenciales.",
            )

        conexion.commit()
        return {
            "mensaje": "Empleado registrado y credenciales enviadas correctamente.",
            "id_usuario": id_usuario,
            "correo_enviado": True,
            "correo_destino": correo,
        }
    except HTTPException:
        if conexion is not None and conexion.is_connected():
            conexion.rollback()
        raise
    except IntegrityError as error:
        if conexion is not None and conexion.is_connected():
            conexion.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="El DUI o correo ya se encuentra registrado.",
        ) from error
    except Error as error:
        if conexion is not None and conexion.is_connected():
            conexion.rollback()
        logger.exception("No se pudo crear el empleado")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No fue posible registrar al empleado.",
        ) from error
    finally:
        if cursor is not None:
            cursor.close()
        if conexion is not None and conexion.is_connected():
            conexion.close()


@app.put("/api/usuarios/{id_usuario}")
def actualizar_empleado(
    id_usuario: int,
    datos: ActualizarEmpleado,
    sesion: dict = Depends(requerir_administrador),
):
    conexion = cursor = None
    try:
        conexion = obtener_conexion()
        cursor = conexion.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT id_usuario, rol, foto
            FROM usuarios
            WHERE id_usuario = %s AND id_empresa = %s
            LIMIT 1
            """,
            (id_usuario, sesion["id_empresa"]),
        )
        actual = cursor.fetchone()
        if actual is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="El empleado no existe dentro de tu empresa.",
            )
        if str(actual["rol"]).lower() != "empleado":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Este modulo solo permite editar empleados.",
            )

        foto = datos.foto if datos.foto is not None else actual.get("foto")
        cursor.execute(
            """
            UPDATE usuarios
            SET nombre = %s, apellido = %s, dui = %s, correo = %s,
                telefono = %s, direccion = %s, foto = %s,
                nombre_usuario = %s, estado = %s
            WHERE id_usuario = %s AND id_empresa = %s AND rol = 'empleado'
            """,
            (
                datos.nombre,
                datos.apellido,
                datos.dui,
                str(datos.correo).lower(),
                datos.telefono,
                datos.direccion,
                foto,
                datos.dui,
                datos.estado,
                id_usuario,
                sesion["id_empresa"],
            ),
        )
        conexion.commit()
        return {"mensaje": "Empleado actualizado correctamente."}
    except HTTPException:
        raise
    except IntegrityError as error:
        if conexion is not None and conexion.is_connected():
            conexion.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="El DUI o correo ya pertenece a otro usuario.",
        ) from error
    except Error as error:
        logger.exception("No se pudo actualizar el empleado")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No fue posible actualizar el empleado.",
        ) from error
    finally:
        if cursor is not None:
            cursor.close()
        if conexion is not None and conexion.is_connected():
            conexion.close()


@app.patch("/api/usuarios/{id_usuario}/estado")
def cambiar_estado_empleado(
    id_usuario: int,
    datos: CambioEstadoUsuario,
    sesion: dict = Depends(requerir_administrador),
):
    if id_usuario == sesion["id_usuario"]:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="No puedes desactivar la cuenta con la sesion activa.",
        )

    conexion = cursor = None
    try:
        conexion = obtener_conexion()
        cursor = conexion.cursor()
        cursor.execute(
            """
            UPDATE usuarios
            SET estado = %s
            WHERE id_usuario = %s AND id_empresa = %s AND rol = 'empleado'
            """,
            (datos.estado, id_usuario, sesion["id_empresa"]),
        )
        if cursor.rowcount == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="El empleado no existe dentro de tu empresa.",
            )
        conexion.commit()
        return {"mensaje": f"Empleado marcado como {datos.estado}."}
    except HTTPException:
        raise
    except Error as error:
        logger.exception("No se pudo cambiar el estado del empleado")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No fue posible cambiar el estado del empleado.",
        ) from error
    finally:
        if cursor is not None:
            cursor.close()
        if conexion is not None and conexion.is_connected():
            conexion.close()


# =============================================================================
# REGISTRO DE EMPRESA Y ADMINISTRADOR
# =============================================================================

@app.post(
    "/api/empresas/registrar",
    response_model=RespuestaRegistro,
    status_code=status.HTTP_201_CREATED,
)
def registrar_empresa(datos: RegistroEmpresa):
    conexion = None
    cursor = None
    try:
        conexion = obtener_conexion()
        conexion.autocommit = False
        cursor = conexion.cursor(dictionary=True)
        conexion.start_transaction()

        correo_empresa = str(datos.empresa.correo).lower()
        correo_admin = str(datos.administrador.correo).lower()

        cursor.execute(
            """
            SELECT id_empresa
            FROM empresas
            WHERE nit = %s OR correo = %s
            LIMIT 1
            """,
            (datos.empresa.nit, correo_empresa),
        )
        if cursor.fetchone() is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Ya existe una empresa con ese NIT o correo electronico.",
            )

        cursor.execute(
            """
            SELECT id_usuario
            FROM usuarios
            WHERE dui = %s OR correo = %s OR nombre_usuario = %s
            LIMIT 1
            """,
            (
                datos.administrador.dui,
                correo_admin,
                datos.administrador.dui,
            ),
        )
        if cursor.fetchone() is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="El DUI o correo del administrador ya esta registrado.",
            )

        codigo_empresa = generar_codigo_empresa(cursor)
        cursor.execute(
            """
            INSERT INTO empresas (
                codigo_empresa,
                nombre_comercial,
                razon_social,
                nit,
                actividad_economica,
                correo,
                telefono,
                direccion,
                estado
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'activa')
            """,
            (
                codigo_empresa,
                datos.empresa.nombre_comercial,
                datos.empresa.razon_social,
                datos.empresa.nit,
                datos.empresa.actividad_economica,
                correo_empresa,
                datos.empresa.telefono,
                datos.empresa.direccion,
            ),
        )
        id_empresa = cursor.lastrowid

        nombre_usuario = datos.administrador.dui
        contrasena_hash = generar_hash_contrasena(datos.administrador.contrasena)
        cursor.execute(
            """
            INSERT INTO usuarios (
                id_empresa,
                nombre,
                apellido,
                dui,
                correo,
                telefono,
                direccion,
                nombre_usuario,
                contrasena_hash,
                rol,
                estado,
                debe_cambiar_contrasena
            ) VALUES (
                %s, %s, %s, %s, %s, %s,
                %s, %s, %s, 'administrador', 'activo', FALSE
            )
            """,
            (
                id_empresa,
                datos.administrador.nombre,
                datos.administrador.apellido,
                datos.administrador.dui,
                correo_admin,
                datos.administrador.telefono,
                datos.administrador.direccion,
                nombre_usuario,
                contrasena_hash,
            ),
        )
        id_administrador = cursor.lastrowid
        conexion.commit()

        correo_enviado, aviso_correo = enviar_correo_bienvenida(
            destinatario=correo_admin,
            nombre_administrador=datos.administrador.nombre,
            nombre_empresa=datos.empresa.nombre_comercial,
            codigo_empresa=codigo_empresa,
            usuario=nombre_usuario,
        )
        return RespuestaRegistro(
            exito=True,
            mensaje="Empresa y administrador registrados correctamente.",
            codigo_empresa=codigo_empresa,
            id_empresa=id_empresa,
            id_administrador=id_administrador,
            usuario=nombre_usuario,
            correo_enviado=correo_enviado,
            correo_destino=correo_admin,
            aviso=aviso_correo,
        )
    except HTTPException:
        if conexion is not None and conexion.is_connected():
            conexion.rollback()
        raise
    except IntegrityError as error:
        if conexion is not None and conexion.is_connected():
            conexion.rollback()
        logger.warning("Registro duplicado o invalido: %s", error)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="No se pudo registrar porque alguno de los datos ya existe.",
        ) from error
    except Error as error:
        if conexion is not None and conexion.is_connected():
            conexion.rollback()
        logger.exception("Error de MySQL al registrar la empresa")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="No fue posible guardar la empresa y el administrador.",
        ) from error
    except Exception as error:
        if conexion is not None and conexion.is_connected():
            conexion.rollback()
        logger.exception("Error inesperado durante el registro")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Ocurrio un error inesperado.",
        ) from error
    finally:
        if cursor is not None:
            cursor.close()
        if conexion is not None and conexion.is_connected():
            conexion.close()
