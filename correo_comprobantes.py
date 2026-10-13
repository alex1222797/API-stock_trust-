"""Envío independiente del cobro: nunca crea ventas ni modifica existencias."""
import base64
import logging
from datetime import datetime, timedelta, timezone
from html import escape
from uuid import uuid4

import requests
from fastapi import Depends, HTTPException
from pydantic import BaseModel, ConfigDict, EmailStr, Field

from comprobante_pdf import crear_comprobante_pdf, importe

log = logging.getLogger('stocktrust.comprobantes')


class CorreoComprobante(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    correo: EmailStr = Field(max_length=254)


def instalar_correo(app, db, ambito, consultar_comprobante, sesion_activa, config):
    def respuesta(fila):
        mensajes = {
            'aceptado': 'El servicio de correo aceptó el comprobante. Revisa también la carpeta de spam.',
            'enviando': 'El comprobante se está enviando. Puedes consultar nuevamente sin repetir el cobro.',
            'fallido': fila.get('detalle') or 'No se pudo enviar. Puedes reintentar sin volver a cobrar.',
            'incierto': 'No se pudo confirmar el envío. Revisa el correo del cliente y los registros de Brevo antes de reenviar.',
        }
        return {'estado': fila['estado'], 'mensaje': mensajes[fila['estado']],
                'correo': fila['correo'], 'id_envio': fila['id_envio']}

    @app.post('/api/ventas/{id_venta}/correo')
    def enviar(id_venta: int, datos: CorreoComprobante, s=Depends(sesion_activa)):
        correo = str(datos.correo)
        where, args = ambito(s)
        with db() as c:
            # Bloqueo breve para impedir dos envíos simultáneos al mismo destinatario.
            c.execute(f'SELECT v.id_venta,v.estado FROM ventas v WHERE {where} AND v.id_venta=%s FOR UPDATE', args + [id_venta])
            venta = c.fetchone()
            if not venta:
                raise HTTPException(404, 'Comprobante no encontrado.')
            if venta['estado'] != 'completada':
                raise HTTPException(409, 'Sólo se envían comprobantes de ventas completadas.')
            c.execute('SELECT * FROM comprobantes_correo WHERE id_venta=%s AND correo=%s', (id_venta, correo))
            previo = c.fetchone()
            if previo and previo['estado'] in ('aceptado', 'incierto', 'enviando'):
                if previo['estado'] == 'enviando':
                    fecha = previo['fecha_actualizacion']
                    if isinstance(fecha, str):
                        fecha = datetime.fromisoformat(fecha)
                    ahora = datetime.now(timezone(timedelta(hours=-6))).replace(tzinfo=None)
                    if ahora - fecha > timedelta(minutes=3):
                        previo['estado'] = 'incierto'
                        c.execute("UPDATE comprobantes_correo SET estado='incierto',fecha_actualizacion=NOW() WHERE id_envio=%s", (previo['id_envio'],))
                return respuesta(previo)
            if not config or not config.get('api_key') or not config.get('sender_email'):
                raise HTTPException(503, 'La venta está guardada, pero falta configurar Brevo en Render.')
            id_envio = previo['id_envio'] if previo else str(uuid4())
            if previo:
                c.execute("UPDATE comprobantes_correo SET estado='enviando',intentos=intentos+1,detalle=NULL,fecha_actualizacion=NOW() WHERE id_envio=%s", (id_envio,))
            else:
                c.execute('''INSERT INTO comprobantes_correo
                    (id_envio,id_venta,id_empresa,correo,estado,intentos,fecha_actualizacion)
                    VALUES (%s,%s,%s,%s,'enviando',1,NOW())''', (id_envio, id_venta, s['id_empresa'], correo))
        # El cobro y el registro del intento ya están confirmados antes de llamar a Brevo.
        estado, detalle, mensaje_id = 'fallido', '', None
        try:
            datos_pdf = consultar_comprobante(id_venta, s)
            venta, productos = datos_pdf['venta'], datos_pdf['productos']
            if venta['estado'] != 'completada':
                raise ValueError('La venta fue anulada antes del envío.')
            pdf = crear_comprobante_pdf(venta, productos)
            numero = str(venta['numero_comprobante'])
            empresa = (venta.get('empresa') or {}).get('nombre_comercial') or 'StockTrust'
            texto = f'Gracias por tu compra en {empresa}.\nComprobante: {numero}\nTotal pagado: {importe(venta["total"])}\nAdjuntamos el detalle de tu compra en PDF.'
            cuerpo = {
                'sender': {'email': config['sender_email'], 'name': config.get('sender_name') or 'StockTrust'},
                'to': [{'email': correo}],
                'subject': f'Tu comprobante de compra {numero}',
                'textContent': texto,
                'htmlContent': '<html lang="es"><body style="font-family:Arial;color:#112B45">'
                               '<h1>Gracias por tu compra</h1><p>' + escape(texto).replace('\n', '<br>') + '</p></body></html>',
                'attachment': [{'name': numero + '.pdf', 'content': base64.b64encode(pdf).decode('ascii')}],
                'tags': ['comprobante-stocktrust'],
            }
        except Exception:
            log.exception('No se pudo preparar comprobante de venta %s', id_venta)
            detalle = 'No se pudo preparar el PDF. La venta está guardada; puedes reintentar.'
        else:
            try:
                r = requests.post(config['url'], headers={'api-key': config['api_key'], 'accept': 'application/json'},
                                  json=cuerpo, timeout=(10, config.get('timeout', 20)))
                if 200 <= r.status_code < 300:
                    mensaje_id = r.json().get('messageId')
                    estado = 'aceptado' if mensaje_id else 'incierto'
                elif r.status_code >= 500 or r.status_code == 408:
                    estado = 'incierto'
                else:
                    detalle = 'El servicio de correo rechazó el envío. Revisa el destinatario, la configuración y el cupo de Brevo; luego reintenta.'
                    log.warning('Brevo rechazó comprobante %s: HTTP %s', id_venta, r.status_code)
            except (requests.RequestException, ValueError, AttributeError, TypeError):
                # Un timeout puede ocurrir DESPUÉS de que el proveedor recibió el correo.
                estado = 'incierto'
                log.warning('Resultado de correo no confirmado para venta %s', id_venta)
        with db() as c:
            c.execute('''UPDATE comprobantes_correo SET estado=%s,detalle=%s,mensaje_id=%s,
                fecha_actualizacion=NOW() WHERE id_envio=%s''', (estado, detalle, mensaje_id, id_envio))
        return respuesta({'estado': estado, 'detalle': detalle, 'correo': correo, 'id_envio': id_envio})
