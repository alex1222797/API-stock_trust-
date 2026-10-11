"""API principal de StockTrust.

Registra empresas junto con su primer administrador y autentica a los
usuarios de la aplicación de escritorio mediante tokens JWT.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import logging
import os
import re
import secrets
import requests
import string
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from typing import Optional

import jwt
import mysql.connector
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


# =============================================================================
# NORMALIZACION Y VALIDACION
# =============================================================================

def limpiar_espacios(valor: str) -> str:
    return " ".join(valor.strip().split())


def limpiar_documento(valor: str) -> str:
    return re.sub(r"\D", "", valor)


PATRON_TELEFONO_SV = re.compile(r"^(?:\+503[\s-]?)?[267]\d{3}-?\d{4}$")
PATRON_DUI = re.compile(r"^\d{8}-\d$")


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
        aviso = "La cuenta se creó, pero Brevo no está configurado."
        logger.warning(aviso)
        return False, aviso

    if not BREVO_CONFIG["sender_email"]:
        aviso = "La cuenta se creó, pero falta configurar el correo remitente."
        logger.warning(aviso)
        return False, aviso

    nombre_seguro = html.escape(nombre_administrador)
    empresa_segura = html.escape(nombre_empresa)
    codigo_seguro = html.escape(codigo_empresa)
    usuario_seguro = html.escape(usuario)

    asunto = "Bienvenido a StockTrust"

    contenido_texto = f"""Hola, {nombre_administrador}.

La empresa {nombre_empresa} fue registrada correctamente en StockTrust.

Código de empresa: {codigo_empresa}
Usuario administrador: {usuario}

Para iniciar sesión utiliza la contraseña que creaste durante el registro.

Por seguridad, StockTrust nunca envía tu contraseña en texto visible.

Sitio oficial:
https://stocktrustinfo.netlify.app/
"""

    contenido_html = f"""
<!doctype html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>

<body style="
    margin:0;
    padding:0;
    background:#eef3f7;
    font-family:Arial,Helvetica,sans-serif;
    color:#112b45;
">
    <table
        role="presentation"
        width="100%"
        cellspacing="0"
        cellpadding="0"
        style="background:#eef3f7;"
    >
        <tr>
            <td align="center" style="padding:32px 16px;">
                <table
                    role="presentation"
                    width="600"
                    cellspacing="0"
                    cellpadding="0"
                    style="
                        width:100%;
                        max-width:600px;
                        overflow:hidden;
                        border-radius:18px;
                        background:#ffffff;
                        box-shadow:0 15px 40px rgba(17,43,69,0.12);
                    "
                >
                    <tr>
                        <td style="
                            padding:30px 36px;
                            color:#ffffff;
                            background:#112b45;
                        ">
                            <h1 style="
                                margin:0;
                                font-size:29px;
                                line-height:1.2;
                            ">
                                StockTrust
                            </h1>

                            <p style="
                                margin:7px 0 0;
                                color:#d8e7f5;
                                font-size:14px;
                            ">
                                Organiza. Controla. Haz crecer.
                            </p>
                        </td>
                    </tr>

                    <tr>
                        <td style="padding:36px;">
                            <p style="
                                margin:0 0 8px;
                                color:#ee6c2b;
                                font-size:13px;
                                font-weight:bold;
                                letter-spacing:1px;
                            ">
                                REGISTRO COMPLETADO
                            </p>

                            <h2 style="
                                margin:0 0 16px;
                                color:#112b45;
                                font-size:25px;
                            ">
                                Bienvenido, {nombre_seguro}
                            </h2>

                            <p style="
                                margin:0;
                                color:#52677a;
                                font-size:15px;
                                line-height:1.7;
                            ">
                                La empresa
                                <strong>{empresa_segura}</strong>
                                fue registrada correctamente en StockTrust.
                            </p>

                            <div style="
                                margin:25px 0;
                                padding:20px;
                                border-left:5px solid #ee6c2b;
                                border-radius:8px;
                                background:#f4f7fa;
                            ">
                                <p style="
                                    margin:0 0 11px;
                                    color:#112b45;
                                ">
                                    <strong>Código de empresa:</strong>
                                    {codigo_seguro}
                                </p>

                                <p style="
                                    margin:0;
                                    color:#112b45;
                                ">
                                    <strong>Usuario administrador:</strong>
                                    {usuario_seguro}
                                </p>
                            </div>

                            <p style="
                                margin:0;
                                color:#52677a;
                                font-size:14px;
                                line-height:1.7;
                            ">
                                Para iniciar sesión utiliza la contraseña que
                                elegiste durante el registro.
                            </p>

                            <p style="
                                margin:12px 0 0;
                                color:#52677a;
                                font-size:14px;
                                line-height:1.7;
                            ">
                                Por seguridad, StockTrust nunca envía ni
                                muestra tu contraseña en texto visible.
                            </p>

                            <p style="margin:28px 0 0;">
                                <a
                                    href="https://stocktrustinfo.netlify.app/"
                                    style="
                                        display:inline-block;
                                        padding:14px 23px;
                                        border-radius:10px;
                                        color:#ffffff;
                                        background:#ee6c2b;
                                        font-size:14px;
                                        font-weight:bold;
                                        text-decoration:none;
                                    "
                                >
                                    Visitar StockTrust
                                </a>
                            </p>
                        </td>
                    </tr>

                    <tr>
                        <td style="
                            padding:20px 36px;
                            color:#718293;
                            background:#f4f7fa;
                            font-size:12px;
                            line-height:1.6;
                        ">
                            Este correo fue enviado automáticamente porque
                            registraste una empresa en StockTrust.
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
"""

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
        "subject": asunto,
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
            "Brevo rechazó el correo. Código %s: %s",
            respuesta.status_code,
            respuesta.text[:500],
        )

        return (
            False,
            "La cuenta se creó, pero el servicio de correo rechazó el envío.",
        )

    except requests.Timeout:
        logger.exception(
            "Brevo tardó demasiado en responder al enviar el correo."
        )

        return (
            False,
            "La cuenta se creó, pero el correo tardó demasiado en enviarse.",
        )

    except requests.RequestException as error:
        logger.exception(
            "No se pudo conectar con la API de Brevo: %s",
            error,
        )

        return (
            False,
            "La cuenta se creó, pero no se pudo conectar con el correo.",
        )

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

    if not JWT_SECRET:
        logger.warning("JWT_SECRET no esta configurada; el login no emitira tokens.")
    yield


app = FastAPI(
    title="StockTrust API",
    description="API de registro y autenticacion para StockTrust.",
    version="1.2.0",
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
        "version": "1.2.0",
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
