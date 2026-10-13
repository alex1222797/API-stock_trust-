"""Endpoints del escritorio. Todas las consultas están limitadas por empresa.

No se aceptan SQL, id_empresa ni id_usuario del cliente para cambiar el ámbito.
Los empleados venden, gestionan productos y ven sus propias ventas; sólo el
administrador ve todas las ventas, anula o administra empleados.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import logging
import re
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, ROUND_HALF_UP
from typing import Literal
from uuid import UUID, uuid4

from fastapi import Depends, HTTPException, Query, Response
from mysql.connector import Error, IntegrityError
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator
from PIL import Image, ImageOps, UnidentifiedImageError

log = logging.getLogger('stocktrust.negocio')
CENTAVO = Decimal('0.01')


def dinero(valor):
    return Decimal(str(valor)).quantize(CENTAVO, rounding=ROUND_HALF_UP)


def normalizar_imagen(valor):
    if valor is None or valor == '':
        return None
    if not re.fullmatch(r'data:image/(?:jpeg|png|webp);base64,[A-Za-z0-9+/=]+', valor):
        raise ValueError('Envía una imagen JPEG, PNG o WebP; no una ruta de tu computadora.')
    try:
        datos = base64.b64decode(valor.split(',', 1)[1], validate=True)
        if len(datos) > 1_000_000:
            raise ValueError('Imagen demasiado grande (máximo 1 MB comprimida).')
        with Image.open(io.BytesIO(datos)) as original:
            if original.width * original.height > 16_000_000:
                raise ValueError('La imagen supera 16 megapíxeles.')
            imagen = ImageOps.exif_transpose(original).convert('RGB')
            imagen.thumbnail((900, 900))
            salida = io.BytesIO()
            imagen.save(salida, 'JPEG', quality=85, optimize=True)
        return 'data:image/jpeg;base64,' + base64.b64encode(salida.getvalue()).decode()
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError) as error:
        raise ValueError('El archivo no es una imagen válida.') from error


class Modelo(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)


class ProductoDatos(Modelo):
    codigo_barras: str = Field(min_length=1, max_length=60)
    nombre: str = Field(min_length=1, max_length=150)
    descripcion: str = Field(default='', max_length=2000)
    categoria: str = Field(min_length=1, max_length=80)
    precio_compra: Decimal = Field(ge=0, max_digits=12, decimal_places=2)
    precio_venta: Decimal = Field(gt=0, max_digits=12, decimal_places=2)
    stock: int = Field(ge=0, le=1_000_000, strict=True)
    stock_minimo: int = Field(ge=0, le=1_000_000, strict=True)
    estado: Literal['activo', 'inactivo'] = 'activo'
    imagen: str | None = Field(default=None, max_length=1_500_000)
    version: int | None = Field(default=None, ge=1)

    @field_validator('imagen')
    @classmethod
    def foto_valida(cls, valor):
        return normalizar_imagen(valor)


class EstadoDatos(Modelo):
    estado: Literal['activo', 'inactivo']


class LineaVenta(Modelo):
    id_producto: int = Field(gt=0, strict=True)
    cantidad: int = Field(gt=0, le=100_000, strict=True)
    precio_esperado: Decimal = Field(gt=0, max_digits=12, decimal_places=2)


class VentaDatos(Modelo):
    solicitud_id: UUID
    productos: list[LineaVenta] = Field(min_length=1, max_length=200)
    descuento: Decimal = Field(ge=0, max_digits=12, decimal_places=2)
    total_esperado: Decimal = Field(ge=0, max_digits=12, decimal_places=2)
    metodo_pago: Literal['efectivo', 'tarjeta', 'transferencia'] = 'efectivo'
    cliente_nombre: str = Field(default='', max_length=120)
    cliente_correo: EmailStr | None = Field(default=None, max_length=254)
    monto_recibido: Decimal | None = Field(default=None, ge=0, max_digits=12, decimal_places=2)
    borrador_revision: UUID | None = None

    @model_validator(mode='after')
    def sin_duplicados(self):
        ids = [p.id_producto for p in self.productos]
        if len(ids) != len(set(ids)):
            raise ValueError('Un producto sólo puede aparecer una vez por venta.')
        return self


class CarritoDatos(Modelo):
    productos: list[LineaVenta] = Field(min_length=1,max_length=200)
    descuento: Decimal = Field(ge=0,max_digits=12,decimal_places=2)
    cliente_nombre: str = Field(default='',max_length=120)


class PerfilDatos(Modelo):
    telefono: str = Field(pattern=r'^[267]\d{3}-?\d{4}$')
    direccion: str = Field(min_length=5, max_length=255)
    foto: str | None = Field(default=None, max_length=1_500_000)

    @field_validator('foto')
    @classmethod
    def foto_valida(cls, valor):
        return normalizar_imagen(valor)


class ClaveDatos(BaseModel):
    model_config = ConfigDict(extra='forbid')
    nueva_contrasena: str = Field(min_length=10, max_length=72)
    confirmacion: str = Field(min_length=10, max_length=72)
    contrasena_actual: str | None = Field(default=None, max_length=72)

    @model_validator(mode='after')
    def segura(self):
        valor = self.nueva_contrasena
        if valor != self.confirmacion:
            raise ValueError('Las contraseñas no coinciden.')
        if not all(re.search(p, valor) for p in (r'[A-Z]', r'[a-z]', r'\d', r'[^A-Za-z0-9]')):
            raise ValueError('Usa mayúscula, minúscula, número y símbolo.')
        return self


def instalar_rutas(app, obtener_conexion, sesion_activa, sesion_identificada,
                   requerir_admin, crear_hash, verificar_hash, crear_token, avisar_cambio, correo_config=None):
    @contextmanager
    def db():
        conexion = cursor = None
        try:
            conexion = obtener_conexion()
            conexion.start_transaction()
            cursor = conexion.cursor(dictionary=True)
            yield cursor
            conexion.commit()
        except IntegrityError as error:
            if conexion:
                conexion.rollback()
            raise HTTPException(409, 'El código o dato único ya existe. Actualiza la lista.') from error
        except Error as error:
            if conexion:
                conexion.rollback()
            log.exception('Error de base de datos')
            raise HTTPException(503, 'No se pudo completar la operación. Revisa la conexión y la migración de la API.') from error
        except Exception:
            if conexion:
                conexion.rollback()
            raise
        finally:
            if cursor:
                cursor.close()
            if conexion:
                conexion.close()

    def una(c, sql, args=()):
        c.execute(sql, args)
        return c.fetchone()

    def todas(c, sql, args=()):
        c.execute(sql, args)
        return c.fetchall()

    def ambito(s, alias='v'):
        condicion = f'{alias}.id_empresa=%s'
        args = [s['id_empresa']]
        if s['rol'] != 'administrador':
            condicion += f' AND {alias}.id_usuario=%s'
            args.append(s['id_usuario'])
        return condicion, args

    def producto_publico(p):
        imagen = p.pop('imagen', None)
        if imagen and imagen.startswith('data:image/'):
            sello = hashlib.sha256(imagen.encode()).hexdigest()[:20]
            p['imagen'] = f"api:/api/imagenes/productos/{p['id_producto']}?v={sello}"
        else:
            p['imagen'] = None
        return p

    def movimiento(c, s, producto, anterior, nuevo, descripcion, venta=None):
        if anterior == nuevo:
            return
        c.execute('''INSERT INTO movimientos_inventario
            (id_producto,id_usuario,id_venta,tipo,cantidad,stock_anterior,stock_nuevo,descripcion)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)''',
            (producto, s['id_usuario'], venta, 'entrada' if nuevo > anterior else 'salida',
             abs(nuevo-anterior), anterior, nuevo, descripcion))

    @app.get('/api/productos/categorias')
    def categorias(s=Depends(sesion_activa)):
        with db() as c:
            filas = todas(c, 'SELECT DISTINCT categoria FROM productos WHERE id_empresa=%s ORDER BY categoria', (s['id_empresa'],))
        return {'categorias': [r['categoria'] for r in filas]}

    @app.get('/api/productos/codigo')
    def por_codigo(codigo: str = Query(min_length=1, max_length=60), s=Depends(sesion_activa)):
        with db() as c:
            p = una(c, 'SELECT * FROM productos WHERE id_empresa=%s AND codigo_barras=%s', (s['id_empresa'], codigo))
        if not p:
            raise HTTPException(404, 'No se encontró el producto.')
        return {'producto': producto_publico(p)}

    @app.get('/api/productos')
    def productos(texto: str = Query('', max_length=150), categoria: str = Query('Todos', max_length=80),
                  solo_activos: bool = False, offset: int = Query(0, ge=0),
                  limit: int = Query(200, ge=1, le=200), s=Depends(sesion_activa)):
        where, args = 'id_empresa=%s', [s['id_empresa']]
        if texto:
            where += ' AND (nombre LIKE %s OR codigo_barras LIKE %s)'
            args += ['%'+texto+'%'] * 2
        if categoria and categoria not in ('Todos', 'Todas'):
            where += ' AND categoria=%s'
            args.append(categoria)
        if solo_activos:
            where += " AND estado='activo'"
        with db() as c:
            filas = todas(c, f'SELECT * FROM productos WHERE {where} ORDER BY nombre,id_producto LIMIT %s OFFSET %s', args+[limit+1,offset])
        return {'productos': [producto_publico(p) for p in filas[:limit]], 'hay_mas': len(filas)>limit}

    @app.post('/api/productos', status_code=201)
    def crear_producto(datos: ProductoDatos, s=Depends(sesion_activa)):
        with db() as c:
            c.execute('''INSERT INTO productos
                (id_empresa,codigo_barras,nombre,descripcion,imagen,categoria,precio_compra,
                 precio_venta,stock,stock_minimo,estado)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                (s['id_empresa'],datos.codigo_barras,datos.nombre,datos.descripcion,datos.imagen,
                 datos.categoria,datos.precio_compra,datos.precio_venta,datos.stock,datos.stock_minimo,datos.estado))
            id_producto = c.lastrowid
            movimiento(c,s,id_producto,0,datos.stock,'Existencia inicial')
        return {'id_producto': id_producto, 'mensaje': 'Producto registrado.'}

    @app.put('/api/productos/{id_producto}')
    def editar_producto(id_producto: int, datos: ProductoDatos, s=Depends(sesion_activa)):
        with db() as c:
            previo = una(c, 'SELECT * FROM productos WHERE id_producto=%s AND id_empresa=%s FOR UPDATE', (id_producto,s['id_empresa']))
            if not previo:
                raise HTTPException(404,'Producto no encontrado.')
            if datos.version is None or datos.version != previo['version']:
                raise HTTPException(409,'El producto cambió (por ejemplo, se realizó una venta). Actualiza y selecciónalo de nuevo antes de editar.')
            imagen = datos.imagen if 'imagen' in datos.model_fields_set else previo['imagen']
            c.execute('''UPDATE productos SET codigo_barras=%s,nombre=%s,descripcion=%s,
                imagen=%s,categoria=%s,precio_compra=%s,precio_venta=%s,stock=%s,stock_minimo=%s,
                estado=%s,version=version+1 WHERE id_producto=%s AND id_empresa=%s''',
                (datos.codigo_barras,datos.nombre,datos.descripcion,imagen,datos.categoria,datos.precio_compra,
                 datos.precio_venta,datos.stock,datos.stock_minimo,datos.estado,id_producto,s['id_empresa']))
            movimiento(c,s,id_producto,previo['stock'],datos.stock,'Ajuste desde Productos')
        return {'mensaje': 'Producto actualizado.'}

    @app.patch('/api/productos/{id_producto}/estado')
    def estado_producto(id_producto: int, datos: EstadoDatos, s=Depends(sesion_activa)):
        with db() as c:
            p = una(c,'SELECT id_producto FROM productos WHERE id_producto=%s AND id_empresa=%s FOR UPDATE',(id_producto,s['id_empresa']))
            if not p:
                raise HTTPException(404,'Producto no encontrado.')
            c.execute('UPDATE productos SET estado=%s,version=version+1 WHERE id_producto=%s AND id_empresa=%s', (datos.estado,id_producto,s['id_empresa']))
        return {'mensaje': 'Estado actualizado.'}

    @app.post('/api/ventas', status_code=201)
    def vender(datos: VentaDatos, s=Depends(sesion_activa)):
        huella = hashlib.sha256(json.dumps(datos.model_dump(mode='json'),sort_keys=True).encode()).hexdigest()
        with db() as c:
            # Serializa cobros del mismo usuario y da idempotencia incluso con dos peticiones concurrentes.
            una(c,'SELECT id_usuario FROM usuarios WHERE id_usuario=%s AND id_empresa=%s FOR UPDATE',(s['id_usuario'],s['id_empresa']))
            anterior = una(c,'SELECT * FROM ventas WHERE id_empresa=%s AND solicitud_id=%s FOR UPDATE',(s['id_empresa'],str(datos.solicitud_id)))
            if anterior:
                if anterior['id_usuario'] != s['id_usuario'] or anterior['solicitud_hash'] != huella:
                    raise HTTPException(409,'La referencia del cobro pertenece a otra operación.')
                return {'id_venta': anterior['id_venta'],'numero_comprobante':anterior['numero_comprobante'],
                        'total':float(anterior['total']),'monto_recibido':anterior.get('monto_recibido'),
                        'cambio':anterior.get('cambio'), 'repetida': True}
            lineas, subtotal = [], Decimal('0.00')
            for item in sorted(datos.productos,key=lambda p:p.id_producto):
                p = una(c,'SELECT * FROM productos WHERE id_producto=%s AND id_empresa=%s FOR UPDATE',(item.id_producto,s['id_empresa']))
                if not p or p['estado'] != 'activo':
                    raise HTTPException(409,'Hay un producto inexistente o inactivo. Actualiza el catálogo.')
                if p['stock'] < item.cantidad:
                    raise HTTPException(409,f"Stock insuficiente para {p['nombre']}. Disponible: {p['stock']}.")
                precio = dinero(p['precio_venta'])
                if precio != item.precio_esperado:
                    raise HTTPException(409,f"El precio de {p['nombre']} cambió. Actualiza el catálogo y vuelve a confirmar.")
                importe = dinero(precio * item.cantidad)
                subtotal += importe
                lineas.append((p,item.cantidad,precio,importe))
            total = dinero(subtotal - datos.descuento)
            if subtotal > Decimal('9999999999.99'):
                raise HTTPException(422,'El importe supera el límite de una venta.')
            if total < 0 or total != datos.total_esperado:
                raise HTTPException(409,'Los totales cambiaron o el descuento supera el subtotal. Revisa el carrito.')
            recibido = dinero(datos.monto_recibido if datos.monto_recibido is not None else total)
            if recibido < total:
                raise HTTPException(422, 'El dinero recibido no cubre el total de la compra.')
            if datos.metodo_pago != 'efectivo' and recibido != total:
                raise HTTPException(422, 'Sólo los pagos en efectivo pueden generar vuelto.')
            cambio = dinero(recibido - total)
            c.execute('''INSERT INTO ventas (id_empresa,id_usuario,numero_comprobante,subtotal,
                      descuento,total,metodo_pago,estado,solicitud_id,solicitud_hash)
                      VALUES (%s,%s,%s,%s,%s,%s,%s,'completada',%s,%s)''',
                      (s['id_empresa'],s['id_usuario'],'P-'+str(datos.solicitud_id),subtotal,datos.descuento,
                       total,datos.metodo_pago,str(datos.solicitud_id),huella))
            id_venta = c.lastrowid
            comprobante = f'ST-{id_venta:08d}'
            c.execute('UPDATE ventas SET numero_comprobante=%s WHERE id_venta=%s',(comprobante,id_venta))
            c.execute('''UPDATE ventas SET cliente_nombre=%s,cliente_correo=%s,monto_recibido=%s,cambio=%s
                WHERE id_venta=%s''', (datos.cliente_nombre, str(datos.cliente_correo) if datos.cliente_correo else None,
                                      recibido, cambio, id_venta))
            for p,cantidad,precio,importe in lineas:
                c.execute('''INSERT INTO detalle_ventas
                          (id_venta,id_producto,cantidad,precio_unitario,subtotal,nombre_producto,codigo_barras)
                          VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                          (id_venta,p['id_producto'],cantidad,precio,importe,p['nombre'],p['codigo_barras']))
                c.execute('UPDATE productos SET stock=stock-%s,version=version+1 WHERE id_producto=%s AND id_empresa=%s',
                          (cantidad,p['id_producto'],s['id_empresa']))
                movimiento(c,s,p['id_producto'],p['stock'],p['stock']-cantidad,'Venta '+comprobante,id_venta)
            if datos.borrador_revision:
                c.execute('DELETE FROM carritos_usuario WHERE id_usuario=%s AND id_empresa=%s AND revision=%s',
                          (s['id_usuario'],s['id_empresa'],str(datos.borrador_revision)))
        return {'id_venta':id_venta,'numero_comprobante':comprobante,'total':float(total),
                'monto_recibido':float(recibido),'cambio':float(cambio),'repetida':False}

    def filtros_ventas(s, q='', empleado=None, estado='', desde=None, hasta=None):
        where, args = ambito(s)
        if q:
            where += ' AND v.numero_comprobante LIKE %s'; args.append('%'+q+'%')
        if empleado is not None:
            where += ' AND v.id_usuario=%s'; args.append(empleado)
        if estado in ('completada','anulada'):
            where += ' AND v.estado=%s'; args.append(estado)
        if desde:
            where += ' AND v.fecha_venta >= %s'; args.append(desde)
        if hasta:
            where += ' AND v.fecha_venta < %s'; args.append(hasta+timedelta(days=1))
        if desde and hasta and desde>hasta:
            raise HTTPException(422,'La fecha inicial no puede ser posterior a la final.')
        return where,args

    SELECT_VENTAS = '''SELECT v.*, v.numero_comprobante comprobante,
        CONCAT(u.nombre,' ',u.apellido) empleado,
        (SELECT COALESCE(SUM(d.cantidad),0) FROM detalle_ventas d WHERE d.id_venta=v.id_venta) articulos
        FROM ventas v JOIN usuarios u ON u.id_usuario=v.id_usuario'''

    @app.get('/api/ventas')
    def listar_ventas(q: str = Query('',max_length=100), empleado: int | None = None,
                      estado: str = '', desde: date | None = None, hasta: date | None = None,
                      offset: int = Query(0,ge=0),limit: int = Query(500,ge=1,le=500),s=Depends(sesion_activa)):
        where,args = filtros_ventas(s,q,empleado,estado,desde,hasta)
        with db() as c:
            filas = todas(c,SELECT_VENTAS+f' WHERE {where} ORDER BY v.fecha_venta DESC,v.id_venta DESC LIMIT %s OFFSET %s',args+[limit+1,offset])
            indicadores = una(c,f'''SELECT COALESCE(SUM(CASE WHEN DATE(v.fecha_venta)=CURDATE()
                AND v.estado='completada' THEN v.total ELSE 0 END),0) total_hoy,
                COALESCE(SUM(DATE(v.fecha_venta)=CURDATE() AND v.estado='completada'),0) operaciones_hoy,
                COALESCE(AVG(CASE WHEN v.estado='completada' THEN v.total END),0) promedio,
                COALESCE(SUM(v.estado='anulada'),0) anuladas FROM ventas v WHERE {where}''',args)
        for fila in filas:
            fila.pop('solicitud_hash',None)
        return {'ventas':filas[:limit],'indicadores':indicadores,'hay_mas':len(filas)>limit}

    @app.get('/api/ventas/{id_venta}')
    def comprobante(id_venta: int,s=Depends(sesion_activa)):
        where,args = ambito(s)
        with db() as c:
            venta = una(c,SELECT_VENTAS+f' WHERE {where} AND v.id_venta=%s',args+[id_venta])
            if not venta:
                raise HTTPException(404,'Comprobante no encontrado.')
            productos = todas(c,'''SELECT COALESCE(NULLIF(d.nombre_producto,''),p.nombre) producto,
                d.cantidad,d.precio_unitario,d.subtotal,d.codigo_barras FROM detalle_ventas d
                LEFT JOIN productos p ON p.id_producto=d.id_producto WHERE d.id_venta=%s ORDER BY d.id_detalle''',(id_venta,))
            venta['empresa'] = una(c,'SELECT nombre_comercial,nit,direccion,telefono FROM empresas WHERE id_empresa=%s',(s['id_empresa'],))
        venta.pop('solicitud_hash',None)
        return {'venta':venta,'productos':productos}

    from correo_comprobantes import instalar_correo
    instalar_correo(app, db, ambito, comprobante, sesion_activa, correo_config)

    @app.post('/api/ventas/{id_venta}/anular')
    def anular(id_venta: int,s=Depends(requerir_admin)):
        with db() as c:
            venta = una(c,'SELECT * FROM ventas WHERE id_venta=%s AND id_empresa=%s FOR UPDATE',(id_venta,s['id_empresa']))
            if not venta:
                raise HTTPException(404,'Venta no encontrada.')
            if venta['estado']=='anulada':
                return {'mensaje':'La venta ya estaba anulada. No se devolvió stock otra vez.'}
            if venta['estado']!='completada':
                raise HTTPException(409,'Esta venta no se puede anular.')
            detalles = todas(c,'SELECT * FROM detalle_ventas WHERE id_venta=%s ORDER BY id_producto',(id_venta,))
            if not detalles:
                raise HTTPException(409,'La venta no contiene detalle; requiere revisión.')
            for d in detalles:
                p = una(c,'SELECT stock FROM productos WHERE id_producto=%s AND id_empresa=%s FOR UPDATE',(d['id_producto'],s['id_empresa']))
                if not p:
                    raise HTTPException(409,'Un producto ya no existe en tu empresa. No se anuló la venta.')
                nuevo = p['stock']+d['cantidad']
                c.execute('UPDATE productos SET stock=%s,version=version+1 WHERE id_producto=%s AND id_empresa=%s',(nuevo,d['id_producto'],s['id_empresa']))
                movimiento(c,s,d['id_producto'],p['stock'],nuevo,'Anulación '+venta['numero_comprobante'],id_venta)
            c.execute("UPDATE ventas SET estado='anulada' WHERE id_venta=%s AND id_empresa=%s",(id_venta,s['id_empresa']))
        return {'mensaje':'Venta anulada. Existencias devueltas.'}

    @app.get('/api/panel/resumen')
    def resumen(s=Depends(sesion_activa)):
        where,args = ambito(s)
        with db() as c:
            hoy = una(c,f"SELECT COUNT(*) cantidad,COALESCE(SUM(v.total),0) total FROM ventas v WHERE {where} AND v.estado='completada' AND DATE(v.fecha_venta)=CURDATE()",args)
            p = una(c,"SELECT COUNT(*) productos,COALESCE(SUM(stock<=stock_minimo),0) stock_bajo FROM productos WHERE id_empresa=%s AND estado='activo'",(s['id_empresa'],))
            mov = todas(c,f"SELECT DATE(v.fecha_venta) fecha,SUM(v.total) total FROM ventas v WHERE {where} AND v.estado='completada' AND v.fecha_venta>=DATE_SUB(CURDATE(),INTERVAL 6 DAY) GROUP BY DATE(v.fecha_venta) ORDER BY fecha",args)
            inv = todas(c,"SELECT nombre,stock,stock_minimo FROM productos WHERE id_empresa=%s AND estado='activo' ORDER BY stock,nombre LIMIT 7",(s['id_empresa'],))
            fecha = una(c,'SELECT CURDATE() hoy')['hoy']
        return {'ventas_hoy':hoy['cantidad'],'total_hoy':hoy['total'],**p,'movimiento':mov,'inventario':inv,'fecha_actual':fecha}

    @app.get('/api/reportes')
    def reportes(periodo: Literal['Días','Semanas','Meses']='Días',s=Depends(sesion_activa)):
        where,args = ambito(s)
        with db() as c:
            hoy = una(c,'SELECT CURDATE() hoy')['hoy']
            if periodo=='Días':
                desde=hoy-timedelta(days=6)
            elif periodo=='Semanas':
                desde=hoy-timedelta(days=hoy.weekday()+49)
            else:
                mes=hoy.year*12+hoy.month-1-5
                desde=date(mes//12,mes%12+1,1)
            where += " AND v.estado='completada' AND v.fecha_venta>=%s AND v.fecha_venta<%s"
            args += [desde,hoy+timedelta(days=1)]
            metricas=una(c,f'SELECT COUNT(*) cantidad,COALESCE(SUM(v.total),0) total,COALESCE(AVG(v.total),0) promedio FROM ventas v WHERE {where}',args)
            top=una(c,f'''SELECT p.nombre nombre,SUM(d.cantidad) cantidad
                FROM ventas v JOIN detalle_ventas d ON d.id_venta=v.id_venta
                JOIN productos p ON p.id_producto=d.id_producto WHERE {where}
                GROUP BY d.id_producto,p.nombre ORDER BY cantidad DESC,d.id_producto LIMIT 1''',args)
            dias=todas(c,f'SELECT DATE(v.fecha_venta) fecha,SUM(v.total) total FROM ventas v WHERE {where} GROUP BY DATE(v.fecha_venta) ORDER BY fecha',args)
            historial=todas(c,SELECT_VENTAS+f' WHERE {where} ORDER BY v.fecha_venta DESC,v.id_venta DESC',args)
        grupos={}
        def grupo(d):
            if periodo=='Semanas':
                return d-timedelta(days=d.weekday())
            return d.replace(day=1) if periodo=='Meses' else d
        d=desde
        while d<=hoy:
            grupos[grupo(d)]=Decimal('0')
            d+=timedelta(days=1)
        for fila in dias:
            grupos[grupo(fila['fecha'])]+=fila['total']
        grafica=[{'etiqueta':('Sem ' if periodo=='Semanas' else '')+k.strftime('%m/%Y' if periodo=='Meses' else '%d/%m'),
                  'total':float(v)} for k,v in grupos.items()]
        for venta in historial:
            venta.pop('solicitud_hash',None)
        return {'resumen':metricas,'producto':top,'grafica':grafica,'historial':historial,'desde':desde,'hasta':hoy}

    @app.get('/api/ventas-empleados')
    def empleados_ventas(s=Depends(requerir_admin)):
        with db() as c:
            return {'usuarios':todas(c,'SELECT id_usuario,nombre,apellido FROM usuarios WHERE id_empresa=%s ORDER BY nombre,apellido',(s['id_empresa'],))}

    @app.get('/api/perfil')
    def perfil(s=Depends(sesion_activa)):
        with db() as c:
            p=una(c,'''SELECT id_usuario,id_empresa,nombre,apellido,dui,correo,direccion,foto,rol,
                telefono,estado,fecha_creacion FROM usuarios WHERE id_usuario=%s AND id_empresa=%s''',(s['id_usuario'],s['id_empresa']))
            estadisticas=una(c,'''SELECT COUNT(*) ventas_totales,COALESCE(SUM(DATE(fecha_venta)=CURDATE()),0) ventas_hoy,
                COALESCE(SUM(CASE WHEN DATE(fecha_venta)=CURDATE() THEN total ELSE 0 END),0) total_hoy,
                MAX(fecha_venta) ultima_venta FROM ventas WHERE id_usuario=%s AND id_empresa=%s AND estado='completada' ''',(s['id_usuario'],s['id_empresa']))
        if p['foto'] and p['foto'].startswith('data:image/'):
            sello=hashlib.sha256(p['foto'].encode()).hexdigest()[:20]
            p['foto']=f"api:/api/imagenes/usuarios/{s['id_usuario']}?v={sello}"
        else:
            p['foto']=None
        return {'perfil':p,'estadisticas':estadisticas}

    @app.put('/api/perfil')
    def editar_perfil(datos: PerfilDatos,s=Depends(sesion_activa)):
        with db() as c:
            if 'foto' in datos.model_fields_set:
                c.execute('UPDATE usuarios SET telefono=%s,direccion=%s,foto=%s WHERE id_usuario=%s AND id_empresa=%s',
                          (datos.telefono,datos.direccion,datos.foto,s['id_usuario'],s['id_empresa']))
            else:
                c.execute('UPDATE usuarios SET telefono=%s,direccion=%s WHERE id_usuario=%s AND id_empresa=%s',
                          (datos.telefono,datos.direccion,s['id_usuario'],s['id_empresa']))
        return {'mensaje':'Perfil actualizado.'}

    @app.get('/api/imagenes/{tipo}/{identificador}')
    def imagen(tipo: Literal['productos','usuarios'],identificador: int,s=Depends(sesion_activa)):
        campo,idcol = ('imagen','id_producto') if tipo=='productos' else ('foto','id_usuario')
        if tipo=='usuarios' and s['rol']!='administrador' and identificador!=s['id_usuario']:
            raise HTTPException(404,'Imagen no encontrada.')
        with db() as c:
            fila=una(c,f'SELECT {campo} dato FROM {tipo} WHERE {idcol}=%s AND id_empresa=%s',(identificador,s['id_empresa']))
        if not fila or not fila['dato'] or not fila['dato'].startswith('data:image/'):
            raise HTTPException(404,'La imagen antigua debe volver a cargarse desde su módulo.')
        prefijo,contenido=fila['dato'].split(',',1)
        return Response(base64.b64decode(contenido),media_type=prefijo[5:].split(';')[0],headers={'Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff'})

    @app.post('/api/auth/cambiar-contrasena')
    def cambiar_clave(datos: ClaveDatos,s=Depends(sesion_identificada)):
        with db() as c:
            usuario=una(c,'SELECT * FROM usuarios WHERE id_usuario=%s AND id_empresa=%s FOR UPDATE',(s['id_usuario'],s['id_empresa']))
            if usuario['auth_version']!=s['auth_version']:
                raise HTTPException(401,'Sesión invalidada. Vuelve a ingresar.')
            if not usuario['debe_cambiar_contrasena']:
                if not datos.contrasena_actual or not verificar_hash(datos.contrasena_actual,usuario['contrasena_hash']):
                    raise HTTPException(403,'La contraseña actual no es correcta.')
            elif usuario['fecha_expiracion_temporal'] and datetime.now(timezone(timedelta(hours=-6))).replace(tzinfo=None)>usuario['fecha_expiracion_temporal']:
                raise HTTPException(403,'La contraseña temporal venció.')
            if verificar_hash(datos.nueva_contrasena,usuario['contrasena_hash']):
                raise HTTPException(409,'Elige una contraseña distinta de la actual.')
            c.execute('''UPDATE usuarios SET contrasena_hash=%s,debe_cambiar_contrasena=0,
                fecha_expiracion_temporal=NULL,contrasena_actualizada_en=NOW(),auth_version=auth_version+1
                WHERE id_usuario=%s AND id_empresa=%s''',(crear_hash(datos.nueva_contrasena),s['id_usuario'],s['id_empresa']))
            c.execute('INSERT INTO auditoria_seguridad (id_usuario,evento,descripcion) VALUES (%s,%s,%s)',
                      (s['id_usuario'],'CAMBIO_CONTRASENA','El usuario cambió su contraseña personal mediante la API.'))
            usuario['auth_version']+=1
            usuario['debe_cambiar_contrasena']=False
            admin=una(c,"SELECT correo FROM usuarios WHERE id_empresa=%s AND rol='administrador' AND estado='activo' ORDER BY id_usuario LIMIT 1",(s['id_empresa'],))
        enviado=avisar_cambio(usuario,admin.get('correo') if admin else None)
        return {'mensaje':'Contraseña actualizada. Las otras sesiones fueron invalidadas.',
                'access_token':crear_token(usuario),'correo_enviado':enviado,
                'aviso':None if enviado else 'Se guardó la contraseña, pero no se pudo enviar la notificación.'}

    @app.get('/api/configuracion')
    def configuracion(s=Depends(sesion_activa)):
        with db() as c:
            fila=una(c,'SELECT preferencias FROM preferencias_usuario WHERE id_usuario=%s AND id_empresa=%s',(s['id_usuario'],s['id_empresa']))
        return {'configuracion':json.loads(fila['preferencias']) if fila else {}}

    @app.get('/api/carrito')
    def carrito(s=Depends(sesion_activa)):
        with db() as c:
            fila=una(c,'SELECT revision,contenido FROM carritos_usuario WHERE id_usuario=%s AND id_empresa=%s',
                     (s['id_usuario'],s['id_empresa']))
        return {'carrito':{'revision':fila['revision'],**json.loads(fila['contenido'])} if fila else None}

    @app.put('/api/carrito')
    def guardar_carrito(datos: CarritoDatos,s=Depends(sesion_activa)):
        revision=str(uuid4())
        with db() as c:
            for item in datos.productos:
                if not una(c,'SELECT id_producto FROM productos WHERE id_producto=%s AND id_empresa=%s',
                           (item.id_producto,s['id_empresa'])):
                    raise HTTPException(404,'Un producto no pertenece a tu catálogo.')
            c.execute('''INSERT INTO carritos_usuario(id_usuario,id_empresa,revision,contenido) VALUES (%s,%s,%s,%s)
                ON DUPLICATE KEY UPDATE revision=VALUES(revision),contenido=VALUES(contenido)''',
                (s['id_usuario'],s['id_empresa'],revision,datos.model_dump_json()))
        return {'mensaje':'Carrito pendiente guardado; no reserva ni descuenta stock.','revision':revision}

    @app.put('/api/configuracion')
    def guardar_configuracion(datos: dict,s=Depends(sesion_activa)):
        permitidas={'tema','idioma','moneda','formato_fecha','formato_hora','tamano_texto','modo_ventana',
            'resolucion','actualizacion','pantalla_inicial','confirmar_salida','recordar_ventana',
            'mostrar_animaciones','mostrar_imagenes','alertas_stock','abrir_comprobante','sonido_escaner'}
        if set(datos)-permitidas or len(json.dumps(datos))>4000 or any(not isinstance(v,(str,bool)) for v in datos.values()):
            raise HTTPException(422,'Preferencias no válidas.')
        with db() as c:
            c.execute('''INSERT INTO preferencias_usuario (id_usuario,id_empresa,preferencias) VALUES (%s,%s,%s)
                ON DUPLICATE KEY UPDATE preferencias=VALUES(preferencias)''',(s['id_usuario'],s['id_empresa'],json.dumps(datos)))
        return {'mensaje':'Preferencias guardadas.'}
