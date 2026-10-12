"""Migración explícita e idempotente. Nunca ejecuta DELETE/TRUNCATE/DROP TABLE.

Primero: python migrar_api.py --revisar
Con respaldo de MySQL: python migrar_api.py --aplicar
Asignar productos sin empresa sólo si conoces su propietario:
python migrar_api.py --aplicar --empresa-productos-antiguos 1
"""
import argparse
from pathlib import Path
from main import obtener_conexion

TABLAS = [
'''CREATE TABLE IF NOT EXISTS productos (
 id_producto INT AUTO_INCREMENT PRIMARY KEY, id_empresa INT NULL,
 codigo_barras VARCHAR(60) NOT NULL,nombre VARCHAR(150) NOT NULL,descripcion TEXT,
 imagen MEDIUMTEXT,categoria VARCHAR(80) NOT NULL,precio_compra DECIMAL(12,2) NOT NULL,
 precio_venta DECIMAL(12,2) NOT NULL,stock INT NOT NULL DEFAULT 0,stock_minimo INT NOT NULL DEFAULT 0,
 estado ENUM('activo','inactivo') NOT NULL DEFAULT 'activo',version INT NOT NULL DEFAULT 1,
 fecha_creacion DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
 fecha_actualizacion DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB''',
'''CREATE TABLE IF NOT EXISTS ventas (
 id_venta INT AUTO_INCREMENT PRIMARY KEY,id_empresa INT NULL,id_usuario INT NOT NULL,
 numero_comprobante VARCHAR(80) NOT NULL UNIQUE,fecha_venta DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
 subtotal DECIMAL(12,2) NOT NULL,descuento DECIMAL(12,2) NOT NULL DEFAULT 0,total DECIMAL(12,2) NOT NULL,
 metodo_pago VARCHAR(30) NOT NULL DEFAULT 'efectivo',estado VARCHAR(20) NOT NULL DEFAULT 'completada',
 solicitud_id VARCHAR(36) NULL,solicitud_hash CHAR(64) NULL,
 FOREIGN KEY(id_usuario) REFERENCES usuarios(id_usuario)
) ENGINE=InnoDB''',
'''CREATE TABLE IF NOT EXISTS detalle_ventas (
 id_detalle INT AUTO_INCREMENT PRIMARY KEY,id_venta INT NOT NULL,id_producto INT NOT NULL,
 cantidad INT NOT NULL,precio_unitario DECIMAL(12,2) NOT NULL,subtotal DECIMAL(12,2) NOT NULL,
 nombre_producto VARCHAR(150) NULL,codigo_barras VARCHAR(60) NULL,
 FOREIGN KEY(id_venta) REFERENCES ventas(id_venta),FOREIGN KEY(id_producto) REFERENCES productos(id_producto)
) ENGINE=InnoDB''',
'''CREATE TABLE IF NOT EXISTS movimientos_inventario (
 id_movimiento INT AUTO_INCREMENT PRIMARY KEY,id_producto INT NOT NULL,id_usuario INT NULL,id_venta INT NULL,
 tipo VARCHAR(30) NOT NULL,cantidad INT NOT NULL,stock_anterior INT NOT NULL,stock_nuevo INT NOT NULL,
 descripcion VARCHAR(255),fecha_movimiento DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(id_producto) REFERENCES productos(id_producto),FOREIGN KEY(id_usuario) REFERENCES usuarios(id_usuario),
 FOREIGN KEY(id_venta) REFERENCES ventas(id_venta)
) ENGINE=InnoDB''',
'''CREATE TABLE IF NOT EXISTS auditoria_seguridad (
 id_auditoria INT AUTO_INCREMENT PRIMARY KEY,id_usuario INT NOT NULL,evento VARCHAR(80) NOT NULL,
 descripcion TEXT,fecha_evento DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(id_usuario) REFERENCES usuarios(id_usuario)
) ENGINE=InnoDB''',
'''CREATE TABLE IF NOT EXISTS preferencias_usuario (
 id_usuario INT PRIMARY KEY,id_empresa INT NOT NULL,preferencias JSON NOT NULL,
 FOREIGN KEY(id_usuario) REFERENCES usuarios(id_usuario)
) ENGINE=InnoDB''',
'''CREATE TABLE IF NOT EXISTS carritos_usuario (
 id_usuario INT PRIMARY KEY,id_empresa INT NOT NULL,revision VARCHAR(36) NOT NULL,contenido JSON NOT NULL,
 FOREIGN KEY(id_usuario) REFERENCES usuarios(id_usuario)
) ENGINE=InnoDB''',
]

NUEVAS={
 'usuarios':{'auth_version':'INT NOT NULL DEFAULT 1','foto':'MEDIUMTEXT NULL',
             'contrasena_actualizada_en':'DATETIME NULL'},
 'productos':{'id_empresa':'INT NULL','version':'INT NOT NULL DEFAULT 1','imagen':'MEDIUMTEXT NULL'},
 'ventas':{'id_empresa':'INT NULL','solicitud_id':'VARCHAR(36) NULL','solicitud_hash':'CHAR(64) NULL',
           'cliente_nombre':"VARCHAR(120) NOT NULL DEFAULT ''"},
 'detalle_ventas':{'nombre_producto':'VARCHAR(150) NULL','codigo_barras':'VARCHAR(60) NULL'},
 'movimientos_inventario':{'id_venta':'INT NULL'},
}


def columnas(c,tabla):
    c.execute(f'SHOW COLUMNS FROM `{tabla}`')
    return {r['Field']:r for r in c.fetchall()}


def ejecutar(aplicar=False, empresa=None, recursos=None):
    conexion=obtener_conexion()
    c=conexion.cursor(dictionary=True)
    try:
        # El registro web ya usa estas dos tablas; no se reemplazan ni se inventan sus dueños.
        for tabla in ('empresas','usuarios'):
            columnas(c,tabla)
        c.execute("SELECT TABLE_NAME,ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('usuarios','productos','ventas','detalle_ventas','movimientos_inventario','auditoria_seguridad')")
        for r in c.fetchall():
            if r['ENGINE']!='InnoDB':
                raise RuntimeError(f"{r['TABLE_NAME']} no es InnoDB. Revisa antes de migrar; no sería transaccional.")
        c.execute("SELECT TRIGGER_NAME FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=DATABASE() AND EVENT_OBJECT_TABLE IN ('productos','ventas','detalle_ventas','movimientos_inventario')")
        triggers=c.fetchall()
        if triggers:
            raise RuntimeError('Hay triggers de negocio: '+', '.join(r['TRIGGER_NAME'] for r in triggers)+'. Revisa su lógica antes de migrar para no duplicar movimientos.')
        if empresa is not None:
            c.execute('SELECT id_empresa FROM empresas WHERE id_empresa=%s',(empresa,))
            if not c.fetchone():
                raise RuntimeError('La empresa indicada no existe.')
        c.execute('SHOW TABLES')
        nombres={next(iter(r.values())) for r in c.fetchall()}
        if not aplicar:
            print('Conexión correcta. Tablas: '+', '.join(sorted(nombres)))
            for tabla,campos in NUEVAS.items():
                cols=columnas(c,tabla) if tabla in nombres else {}
                print(tabla+': columnas por agregar = '+', '.join(k for k in campos if k not in cols))
            if 'productos' in nombres:
                cols=columnas(c,'productos')
                c.execute('SELECT COUNT(*) cantidad FROM productos'+(' WHERE id_empresa IS NULL' if 'id_empresa' in cols else ''))
                print('Productos sin empresa:',c.fetchone()['cantidad'])
            print('Sólo revisión; no se modificó la base. Haz respaldo y usa --aplicar.')
            return
        # DDL MySQL hace commit implícito; si se interrumpe, se puede volver a ejecutar.
        for sql in TABLAS:
            c.execute(sql)
        for tabla,campos in NUEVAS.items():
            cols=columnas(c,tabla)
            for nombre,tipo in campos.items():
                if nombre not in cols:
                    c.execute(f'ALTER TABLE `{tabla}` ADD COLUMN `{nombre}` {tipo}')
        for tabla,campo in (('productos','imagen'),('usuarios','foto')):
            tipo=columnas(c,tabla)[campo]['Type'].lower()
            if tipo not in ('mediumtext','longtext'):
                c.execute(f'ALTER TABLE `{tabla}` MODIFY `{campo}` MEDIUMTEXT NULL')
        c.execute("ALTER TABLE usuarios MODIFY rol ENUM('administrador','empleado','vendedor') NOT NULL")
        c.execute("UPDATE usuarios SET rol='empleado',auth_version=auth_version+1 WHERE rol='vendedor'")
        c.execute("ALTER TABLE usuarios MODIFY rol ENUM('administrador','empleado') NOT NULL")
        for tabla,nombre,campos,unico in (
            ('productos','uq_producto_empresa_codigo','id_empresa,codigo_barras',True),
            ('ventas','uq_venta_solicitud','id_empresa,solicitud_id',True),
            ('ventas','ix_venta_empresa_fecha','id_empresa,fecha_venta',False),
        ):
            c.execute(f'SHOW INDEX FROM `{tabla}`')
            existentes=c.fetchall()
            if nombre not in {r['Key_name'] for r in existentes}:
                c.execute(f"CREATE {'UNIQUE ' if unico else ''}INDEX `{nombre}` ON `{tabla}` ({campos})")
        # El código de barras es único POR empresa, no global.
        c.execute('SHOW INDEX FROM productos')
        indices={}
        for r in c.fetchall():
            if r['Non_unique']==0:
                indices.setdefault(r['Key_name'],[]).append(r['Column_name'])
        for nombre,campos in indices.items():
            if campos==['codigo_barras']:
                c.execute('ALTER TABLE productos DROP INDEX `'+nombre.replace('`','``')+'`')
        c.execute('''UPDATE ventas v JOIN usuarios u ON u.id_usuario=v.id_usuario
            SET v.id_empresa=u.id_empresa WHERE v.id_empresa IS NULL AND u.id_empresa IS NOT NULL''')
        if empresa is not None:
            c.execute('UPDATE productos SET id_empresa=%s WHERE id_empresa IS NULL',(empresa,))
            print('Productos antiguos asignados:',c.rowcount)
        c.execute('''UPDATE detalle_ventas d JOIN productos p ON p.id_producto=d.id_producto
            SET d.nombre_producto=p.nombre,d.codigo_barras=p.codigo_barras WHERE d.nombre_producto IS NULL''')
        if recursos:
            migrar_fotos(c,Path(recursos).resolve())
        conexion.commit()
        c.execute('SELECT COUNT(*) cantidad FROM productos WHERE id_empresa IS NULL')
        print('Migración completada. Productos sin empresa (ocultos hasta asignación):',c.fetchone()['cantidad'])
        print('Cierra las sesiones anteriores e inicia sesión de nuevo.')
    finally:
        c.close()
        conexion.close()


def migrar_fotos(c,raiz):
    import base64
    from negocio_api import normalizar_imagen
    for tabla,idcol,campo in (('productos','id_producto','imagen'),('usuarios','id_usuario','foto')):
        c.execute(f'SELECT {idcol} id,{campo} ruta FROM {tabla} WHERE {campo} IS NOT NULL')
        filas=c.fetchall()
        for fila in filas:
            valor=fila['ruta']
            if not valor or valor.startswith('data:'):
                continue
            ruta=(raiz/valor.replace('\\','/')).resolve()
            if not ruta.is_relative_to(raiz) or ruta.suffix.lower() not in ('.png','.jpg','.jpeg','.webp') or not ruta.is_file():
                print(f"Foto no encontrada, volver a seleccionar: {tabla} #{fila['id']}")
                continue
            if ruta.stat().st_size>1_000_000:
                print(f"Foto demasiado grande: {tabla} #{fila['id']}; volver a seleccionar.")
                continue
            mime='jpeg' if ruta.suffix.lower() in ('.jpg','.jpeg') else ruta.suffix[1:]
            foto=normalizar_imagen('data:image/'+mime+';base64,'+base64.b64encode(ruta.read_bytes()).decode())
            c.execute(f'UPDATE {tabla} SET {campo}=%s WHERE {idcol}=%s',(foto,fila['id']))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    modo=p.add_mutually_exclusive_group(required=True)
    modo.add_argument('--revisar',action='store_true')
    modo.add_argument('--aplicar',action='store_true')
    p.add_argument('--empresa-productos-antiguos',type=int)
    p.add_argument('--recursos',help='Carpeta Stock_trust con las fotos antiguas (opcional).')
    a=p.parse_args()
    ejecutar(a.aplicar,a.empresa_productos_antiguos,a.recursos)
