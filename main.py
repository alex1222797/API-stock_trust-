import hashlib
import html
import logging
import os
import re
import secrets
import smtplib
import ssl
import string
from contextlib import asynccontextmanager
from datetime import datetime
from email.message import EmailMessage
from typing import Optional

import mysql.connector
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from mysql.connector import Error, IntegrityError
from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    field_validator,
    model_validator
)


# =========================================================
# VARIABLES DE ENTORNO
# =========================================================

load_dotenv()


logger = logging.getLogger("stocktrust.api")
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
)


DB_CONFIG = {
    "host": os.getenv("MYSQL_HOST", "localhost"),
    "port": int(os.getenv("MYSQL_PORT", "3306")),
    "user": os.getenv("MYSQL_USER", "root"),
    "password": os.getenv("MYSQL_PASSWORD", ""),
    "database": os.getenv("MYSQL_DATABASE", "stock_trust"),
    "charset": "utf8mb4"
}


SMTP_CONFIG = {
    "host": os.getenv("SMTP_HOST", "smtp.gmail.com").strip(),
    "port": int(os.getenv("SMTP_PORT", "587")),
    "user": os.getenv("STOCKTRUST_EMAIL", "").strip(),
    "password": os.getenv("STOCKTRUST_EMAIL_PASSWORD", "").strip(),
    "from_name": os.getenv(
        "STOCKTRUST_EMAIL_FROM_NAME",
        "StockTrust"
    ).strip(),
    "timeout": int(os.getenv("SMTP_TIMEOUT", "20"))
}


# =========================================================
# CONEXIÓN CON MYSQL
# =========================================================

def obtener_conexion():
    """
    Crea una nueva conexión con la base de datos.

    Cada solicitud abre su propia conexión y la cierra cuando
    termina, evitando mantener conexiones abandonadas.
    """
    return mysql.connector.connect(**DB_CONFIG)


# =========================================================
# SEGURIDAD DE CONTRASEÑAS
# =========================================================

def generar_hash_contrasena(contrasena: str) -> str:
    """
    Convierte la contraseña en un hash PBKDF2-SHA256.

    La contraseña original nunca se guarda en MySQL.

    Ejemplo del resultado:
    pbkdf2_sha256$310000$salt$hash
    """
    iteraciones = 310_000
    salt = secrets.token_urlsafe(16)

    hash_bytes = hashlib.pbkdf2_hmac(
        "sha256",
        contrasena.encode("utf-8"),
        salt.encode("utf-8"),
        iteraciones
    )

    # La aplicación de escritorio de StockTrust representa el resultado
    # de PBKDF2 como una cadena hexadecimal de 64 caracteres.
    hash_codificado = hash_bytes.hex()

    return (
        f"pbkdf2_sha256${iteraciones}"
        f"${salt}${hash_codificado}"
    )


# =========================================================
# FUNCIONES DE NORMALIZACIÓN
# =========================================================

def limpiar_espacios(valor: str) -> str:
    """
    Elimina espacios sobrantes al inicio, al final y entre palabras.
    """
    return " ".join(valor.strip().split())


def limpiar_documento(valor: str) -> str:
    """
    Conserva únicamente números.
    """
    return re.sub(r"\D", "", valor)


# =========================================================
# MODELO: DATOS DE LA EMPRESA
# =========================================================

class DatosEmpresa(BaseModel):
    model_config = ConfigDict(extra="forbid")

    nombre_comercial: str = Field(
        min_length=2,
        max_length=120
    )

    razon_social: str = Field(
        min_length=2,
        max_length=150
    )

    nit: str = Field(
        min_length=9,
        max_length=20
    )

    actividad_economica: str = Field(
        min_length=2,
        max_length=150
    )

    correo: EmailStr

    telefono: str = Field(
        min_length=8,
        max_length=20
    )

    direccion: str = Field(
        min_length=10,
        max_length=255
    )

    @field_validator(
        "nombre_comercial",
        "razon_social",
        "actividad_economica",
        "direccion",
        mode="before"
    )
    @classmethod
    def normalizar_textos(cls, valor):
        if not isinstance(valor, str):
            return valor

        return limpiar_espacios(valor)

    @field_validator("nit")
    @classmethod
    def validar_nit(cls, valor: str):
        nit_limpio = limpiar_documento(valor)

        # Se aceptan las presentaciones más comunes para pruebas.
        if len(nit_limpio) not in (9, 14):
            raise ValueError(
                "El NIT debe contener 9 o 14 dígitos."
            )

        return nit_limpio

    @field_validator("telefono")
    @classmethod
    def validar_telefono_empresa(cls, valor: str):
        telefono = valor.strip()

        # Números salvadoreños:
        # 2222-2222
        # 6000-0000
        # 7000-0000
        # +503 7000-0000
        patron = r"^(?:\+503[\s-]?)?[267]\d{3}-?\d{4}$"

        if not re.fullmatch(patron, telefono):
            raise ValueError(
                "Ingresá un teléfono salvadoreño válido."
            )

        return telefono


# =========================================================
# MODELO: DATOS DEL ADMINISTRADOR
# =========================================================

class DatosAdministrador(BaseModel):
    model_config = ConfigDict(extra="forbid")

    nombre: str = Field(
        min_length=2,
        max_length=60
    )

    apellido: str = Field(
        min_length=2,
        max_length=60
    )

    dui: str = Field(
        min_length=10,
        max_length=10
    )

    correo: EmailStr

    telefono: str = Field(
        min_length=8,
        max_length=20
    )

    direccion: str = Field(
        min_length=10,
        max_length=255
    )

    contrasena: str = Field(
        min_length=10,
        max_length=72
    )

    confirmar_contrasena: str = Field(
        min_length=10,
        max_length=72
    )

    @field_validator(
        "nombre",
        "apellido",
        "direccion",
        mode="before"
    )
    @classmethod
    def normalizar_textos(cls, valor):
        if not isinstance(valor, str):
            return valor

        return limpiar_espacios(valor)

    @field_validator("dui")
    @classmethod
    def validar_dui(cls, valor: str):
        dui = valor.strip()

        if not re.fullmatch(r"\d{8}-\d", dui):
            raise ValueError(
                "El DUI debe tener el formato 00000000-0."
            )

        return dui

    @field_validator("telefono")
    @classmethod
    def validar_telefono_administrador(cls, valor: str):
        telefono = valor.strip()
        patron = r"^(?:\+503[\s-]?)?[267]\d{3}-?\d{4}$"

        if not re.fullmatch(patron, telefono):
            raise ValueError(
                "Ingresá un teléfono salvadoreño válido."
            )

        return telefono

    @field_validator("contrasena")
    @classmethod
    def validar_seguridad_contrasena(cls, valor: str):
        errores = []

        if not re.search(r"[A-Z]", valor):
            errores.append("una letra mayúscula")

        if not re.search(r"[a-z]", valor):
            errores.append("una letra minúscula")

        if not re.search(r"\d", valor):
            errores.append("un número")

        if not re.search(r"[^A-Za-z0-9]", valor):
            errores.append("un carácter especial")

        if errores:
            raise ValueError(
                "La contraseña debe incluir "
                + ", ".join(errores)
                + "."
            )

        return valor

    @model_validator(mode="after")
    def comprobar_contrasenas(self):
        if self.contrasena != self.confirmar_contrasena:
            raise ValueError(
                "Las contraseñas no coinciden."
            )

        return self


# =========================================================
# MODELO: SOLICITUD COMPLETA DEL FORMULARIO
# =========================================================

class RegistroEmpresa(BaseModel):
    model_config = ConfigDict(extra="forbid")

    empresa: DatosEmpresa
    administrador: DatosAdministrador
    acepta_terminos: bool

    @field_validator("acepta_terminos")
    @classmethod
    def comprobar_terminos(cls, valor: bool):
        if valor is not True:
            raise ValueError(
                "Debés aceptar los términos y condiciones."
            )

        return valor


# =========================================================
# MODELO: RESPUESTA DE LA API
# =========================================================

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


# =========================================================
# CORREO DE BIENVENIDA
# =========================================================

def enviar_correo_bienvenida(
    destinatario: str,
    nombre_administrador: str,
    nombre_empresa: str,
    codigo_empresa: str,
    usuario: str
) -> tuple[bool, Optional[str]]:
    """
    Envía las instrucciones de acceso al administrador.

    La contraseña no se incluye en el correo. El usuario debe utilizar la
    contraseña que eligió en el formulario; enviarla como texto plano
    convertiría el buzón en una copia innecesaria de sus credenciales.
    """
    if not SMTP_CONFIG["user"] or not SMTP_CONFIG["password"]:
        logger.warning(
            "Correo omitido: faltan STOCKTRUST_EMAIL o "
            "STOCKTRUST_EMAIL_PASSWORD."
        )
        return (
            False,
            "La empresa fue creada, pero el correo de bienvenida no está "
            "configurado en el servidor."
        )

    mensaje = EmailMessage()
    mensaje["Subject"] = "Bienvenido a StockTrust: tu cuenta está lista"
    mensaje["From"] = (
        f'{SMTP_CONFIG["from_name"]} <{SMTP_CONFIG["user"]}>'
    )
    mensaje["To"] = destinatario

    contenido_texto = f"""Hola, {nombre_administrador}:

La empresa {nombre_empresa} fue registrada correctamente en StockTrust.

Código de empresa: {codigo_empresa}
Usuario administrador (DUI): {usuario}
Contraseña: utiliza la contraseña que elegiste durante el registro.

Por seguridad, StockTrust no envía ni almacena tu contraseña en texto plano.
No compartas tus credenciales con otras personas.

StockTrust
Organiza. Controla. Haz crecer.
"""
    mensaje.set_content(contenido_texto)

    nombre_seguro = html.escape(nombre_administrador)
    empresa_segura = html.escape(nombre_empresa)
    codigo_seguro = html.escape(codigo_empresa)
    usuario_seguro = html.escape(usuario)

    mensaje.add_alternative(
        f"""
<!doctype html>
<html lang="es">
<body style="margin:0;background:#eef3f7;font-family:Arial,sans-serif;color:#182434">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0"
         style="background:#eef3f7;padding:30px 12px">
    <tr><td align="center">
      <table role="presentation" width="100%" cellspacing="0" cellpadding="0"
             style="max-width:620px;background:#ffffff;border-radius:18px;overflow:hidden">
        <tr><td style="padding:25px 30px;background:#112b45;color:#ffffff">
          <strong style="font-size:25px">StockTrust</strong><br>
          <span style="color:#ee6c2b;font-size:12px;font-weight:bold">
            ORGANIZA. CONTROLA. HAZ CRECER.
          </span>
        </td></tr>
        <tr><td style="padding:32px 30px">
          <p style="margin:0 0 10px;color:#1d64b4;font-weight:bold">
            REGISTRO COMPLETADO
          </p>
          <h1 style="margin:0 0 14px;color:#112b45;font-size:27px">
            Bienvenido, {nombre_seguro}
          </h1>
          <p style="line-height:1.65">
            <strong>{empresa_segura}</strong> ya está registrada en StockTrust.
            Usa la siguiente información para ingresar a la aplicación.
          </p>
          <div style="margin:24px 0;padding:20px;border-left:5px solid #ee6c2b;background:#f4f7fa">
            <p style="margin:0 0 10px">
              <strong>Código de empresa:</strong> {codigo_seguro}
            </p>
            <p style="margin:0 0 10px">
              <strong>Usuario administrador (DUI):</strong> {usuario_seguro}
            </p>
            <p style="margin:0">
              <strong>Contraseña:</strong> la que elegiste durante el registro.
            </p>
          </div>
          <p style="font-size:14px;line-height:1.6;color:#5c6b7d">
            Por seguridad no enviamos tu contraseña por correo. No compartas
            tus credenciales y utiliza una cuenta individual para cada empleado.
          </p>
        </td></tr>
        <tr><td style="padding:18px 30px;background:#1d64b4;color:#ffffff;text-align:center">
          Control inteligente, inventario confiable.
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>
""",
        subtype="html"
    )

    try:
        contexto_tls = ssl.create_default_context()

        with smtplib.SMTP(
            SMTP_CONFIG["host"],
            SMTP_CONFIG["port"],
            timeout=SMTP_CONFIG["timeout"]
        ) as servidor:
            servidor.ehlo()
            servidor.starttls(context=contexto_tls)
            servidor.ehlo()
            servidor.login(
                SMTP_CONFIG["user"],
                SMTP_CONFIG["password"]
            )
            servidor.send_message(mensaje)

        logger.info("Correo de bienvenida enviado a %s.", destinatario)
        return True, None

    except (OSError, smtplib.SMTPException) as error:
        logger.error("No se pudo enviar el correo de bienvenida: %s", error)
        return (
            False,
            "La empresa fue creada, pero no se pudo enviar el correo de "
            "bienvenida. Conserva el DUI utilizado como usuario."
        )


# =========================================================
# GENERACIÓN DEL CÓDIGO DE EMPRESA
# =========================================================

def generar_codigo_empresa(cursor) -> str:
    """
    Genera un código público como:

    ST-2026-A8F2K9

    También comprueba que el código no exista previamente.
    """
    caracteres = string.ascii_uppercase + string.digits
    anio_actual = datetime.now().year

    for _ in range(10):
        codigo_aleatorio = "".join(
            secrets.choice(caracteres)
            for _ in range(6)
        )

        codigo = f"ST-{anio_actual}-{codigo_aleatorio}"

        cursor.execute(
            """
            SELECT id_empresa
            FROM empresas
            WHERE codigo_empresa = %s
            LIMIT 1
            """,
            (codigo,)
        )

        if cursor.fetchone() is None:
            return codigo

    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="No se pudo generar el código de la empresa."
    )


# =========================================================
# INICIO Y CIERRE DE FASTAPI
# =========================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Verifica MySQL cuando la API inicia.
    """
    conexion = None

    try:
        conexion = obtener_conexion()
        logger.info("StockTrust API conectada correctamente con MySQL.")

    except Error as error:
        logger.error("No se pudo conectar con MySQL: %s", error)

    finally:
        if conexion is not None and conexion.is_connected():
            conexion.close()

    yield


# =========================================================
# CREACIÓN DE LA APLICACIÓN FASTAPI
# =========================================================

app = FastAPI(
    title="StockTrust API",
    description=(
        "API para registrar empresas y crear "
        "su primer usuario administrador."
    ),
    version="1.1.0",
    lifespan=lifespan
)


# =========================================================
# CONFIGURACIÓN DE CORS
# =========================================================

origenes_permitidos = [
    "http://127.0.0.1:5500",
    "http://localhost:5500",
    "http://127.0.0.1:8000",
    "http://localhost:8000",
    "https://stocktrustin.netlify.app",
    "https://stocktrustinfo.netlify.app"
]

frontend_url = os.getenv("FRONTEND_URL")
netlify_url = os.getenv("NETLIFY_URL")

if frontend_url:
    origenes_permitidos.append(frontend_url.rstrip("/"))

if netlify_url:
    origenes_permitidos.append(netlify_url.rstrip("/"))

# Eliminamos orígenes repetidos.
origenes_permitidos = list(set(origenes_permitidos))

app.add_middleware(
    CORSMiddleware,
    allow_origins=origenes_permitidos,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"]
)


# =========================================================
# RUTA PRINCIPAL
# =========================================================

@app.get("/")
def inicio():
    return {
        "aplicacion": "StockTrust API",
        "version": "1.1.0",
        "documentacion": "/docs"
    }


# =========================================================
# COMPROBAR ESTADO DE LA API Y MYSQL
# =========================================================

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
            "base_datos": "conectada"
        }

    except Error as error:
        logger.error("Error de conexión: %s", error)

        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "La API está funcionando, "
                "pero MySQL no está disponible."
            )
        )

    finally:
        if cursor is not None:
            cursor.close()

        if conexion is not None and conexion.is_connected():
            conexion.close()


# =========================================================
# REGISTRAR EMPRESA Y ADMINISTRADOR
# =========================================================

@app.post(
    "/api/empresas/registrar",
    response_model=RespuestaRegistro,
    status_code=status.HTTP_201_CREATED
)
def registrar_empresa(datos: RegistroEmpresa):
    """
    Guarda la empresa y crea su primer administrador.

    Si falla cualquiera de los dos INSERT, se ejecuta rollback
    y no se guarda ningún registro incompleto.
    """
    conexion = None
    cursor = None

    try:
        conexion = obtener_conexion()

        # Desactivamos confirmaciones automáticas.
        conexion.autocommit = False

        cursor = conexion.cursor(dictionary=True)

        # Inicia la transacción antes de realizar consultas.
        conexion.start_transaction()

        correo_empresa = str(datos.empresa.correo).lower()
        correo_admin = str(datos.administrador.correo).lower()

        # -------------------------------------------------
        # COMPROBAR SI LA EMPRESA YA ESTÁ REGISTRADA
        # -------------------------------------------------

        cursor.execute(
            """
            SELECT
                id_empresa,
                nit,
                correo
            FROM empresas
            WHERE nit = %s
               OR correo = %s
            LIMIT 1
            """,
            (
                datos.empresa.nit,
                correo_empresa
            )
        )

        empresa_existente = cursor.fetchone()

        if empresa_existente is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Ya existe una empresa registrada "
                    "con ese NIT o correo electrónico."
                )
            )

        # -------------------------------------------------
        # COMPROBAR SI EL ADMINISTRADOR YA EXISTE
        # -------------------------------------------------

        cursor.execute(
            """
            SELECT
                id_usuario,
                dui,
                correo,
                nombre_usuario
            FROM usuarios
            WHERE dui = %s
               OR correo = %s
               OR nombre_usuario = %s
            LIMIT 1
            """,
            (
                datos.administrador.dui,
                correo_admin,
                datos.administrador.dui
            )
        )

        administrador_existente = cursor.fetchone()

        if administrador_existente is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "El DUI o correo del administrador "
                    "ya está registrado."
                )
            )

        # -------------------------------------------------
        # GENERAR CÓDIGO PÚBLICO DE EMPRESA
        # -------------------------------------------------

        codigo_empresa = generar_codigo_empresa(cursor)

        # -------------------------------------------------
        # GUARDAR LA EMPRESA
        # -------------------------------------------------

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
            )
            VALUES (
                %s, %s, %s, %s, %s,
                %s, %s, %s, 'activa'
            )
            """,
            (
                codigo_empresa,
                datos.empresa.nombre_comercial,
                datos.empresa.razon_social,
                datos.empresa.nit,
                datos.empresa.actividad_economica,
                correo_empresa,
                datos.empresa.telefono,
                datos.empresa.direccion
            )
        )

        id_empresa = cursor.lastrowid

        # -------------------------------------------------
        # CREAR CREDENCIALES DEL ADMINISTRADOR
        # -------------------------------------------------

        # Por acuerdo, el usuario para iniciar sesión será el DUI.
        nombre_usuario = datos.administrador.dui

        # Nunca se almacena la contraseña original.
        contrasena_hash = generar_hash_contrasena(
            datos.administrador.contrasena
        )

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
            )
            VALUES (
                %s, %s, %s, %s, %s, %s,
                %s, %s, %s,
                'administrador',
                'activo',
                FALSE
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
                contrasena_hash
            )
        )

        id_administrador = cursor.lastrowid

        # Confirma empresa y administrador.
        conexion.commit()

        correo_enviado, aviso_correo = enviar_correo_bienvenida(
            destinatario=correo_admin,
            nombre_administrador=datos.administrador.nombre,
            nombre_empresa=datos.empresa.nombre_comercial,
            codigo_empresa=codigo_empresa,
            usuario=nombre_usuario
        )

        return RespuestaRegistro(
            exito=True,
            mensaje=(
                "Empresa y administrador registrados correctamente."
            ),
            codigo_empresa=codigo_empresa,
            id_empresa=id_empresa,
            id_administrador=id_administrador,
            usuario=nombre_usuario,
            correo_enviado=correo_enviado,
            correo_destino=correo_admin,
            aviso=aviso_correo
        )

    except HTTPException:
        if conexion is not None and conexion.is_connected():
            conexion.rollback()

        raise

    except IntegrityError as error:
        if conexion is not None and conexion.is_connected():
            conexion.rollback()

        logger.warning("Registro duplicado o inválido: %s", error)

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "No se pudo completar el registro porque "
                "alguno de los datos ya existe."
            )
        )

    except Error as error:
        if conexion is not None and conexion.is_connected():
            conexion.rollback()

        logger.error("Error de MySQL: %s", error)

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "Ocurrió un error al guardar la empresa "
                "y el administrador."
            )
        )

    except Exception as error:
        if conexion is not None and conexion.is_connected():
            conexion.rollback()

        logger.exception("Error inesperado: %s", error)

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Ocurrió un error inesperado."
        )

    finally:
        if cursor is not None:
            cursor.close()

        if conexion is not None and conexion.is_connected():
            conexion.close()
