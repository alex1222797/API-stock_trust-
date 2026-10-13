"""Comprobantes generados con los datos guardados por la API, no por el cliente."""
from datetime import datetime
from decimal import Decimal, ROUND_HALF_UP
from html import escape
from io import BytesIO
from pathlib import Path

import reportlab
from reportlab.lib import colors
from reportlab.lib.enums import TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import Image, KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

# Fuentes incluidas por ReportLab: se incrustan para conservar el diseño en otra PC.
_fuentes = Path(reportlab.__file__).resolve().parent / 'fonts'
pdfmetrics.registerFont(TTFont('STRegular', str(_fuentes / 'Vera.ttf')))
pdfmetrics.registerFont(TTFont('STBold', str(_fuentes / 'VeraBd.ttf')))


def importe(valor):
    return f"${Decimal(str(valor or 0)).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP):,.2f}"


def crear_comprobante_pdf(venta, productos):
    salida = BytesIO()
    azul = colors.HexColor('#112B45')
    naranja = colors.HexColor('#EE6C2B')
    gris = colors.HexColor('#F1F5F9')
    texto = ParagraphStyle('texto', fontName='STRegular', fontSize=9, leading=13, textColor=azul)
    titulo = ParagraphStyle('titulo', parent=texto, fontName='STBold', fontSize=20, leading=25)
    derecha = ParagraphStyle('derecha', parent=texto, alignment=TA_RIGHT)
    cabecera = ParagraphStyle('cabecera', parent=texto, fontName='STBold', textColor=colors.white)
    total_estilo = ParagraphStyle('total', parent=derecha, fontName='STBold', fontSize=14, leading=19)

    def p(valor, estilo=texto):
        return Paragraph(escape(str(valor or '')).replace('\n', '<br/>'), estilo)

    doc = SimpleDocTemplate(salida, pagesize=A4, rightMargin=36, leftMargin=36,
                            topMargin=32, bottomMargin=42, title=str(venta['numero_comprobante']),
                            author='StockTrust')
    ancho = A4[0] - 72
    empresa = venta.get('empresa') or {}
    logo = Path(__file__).resolve().parent / 'assets' / 'logo.png'
    marca = Image(str(logo), width=52, height=52, kind='proportional') if logo.is_file() else p('STOCKTRUST')
    encabezado = Table([[marca, [p(empresa.get('nombre_comercial') or 'StockTrust', titulo),
                                  p('COMPROBANTE DE COMPRA'), p(venta['numero_comprobante'])]]],
                       colWidths=[70, ancho - 70])
    encabezado.setStyle(TableStyle([('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                                    ('LINEBELOW', (0, 0), (-1, -1), 2, naranja),
                                    ('BOTTOMPADDING', (0, 0), (-1, -1), 14)]))
    contenido = [encabezado, Spacer(1, 12)]
    for campo, etiqueta in (('direccion', 'Dirección'), ('telefono', 'Teléfono'), ('nit', 'NIT')):
        if empresa.get(campo):
            contenido.append(p(f'{etiqueta}: {empresa[campo]}'))
    fecha = venta.get('fecha_venta')
    if isinstance(fecha, str):
        try:
            fecha = datetime.fromisoformat(fecha)
        except ValueError:
            pass
    if isinstance(fecha, datetime):
        fecha = fecha.strftime('%d/%m/%Y %I:%M %p')
    contenido += [Spacer(1, 12), p(f'Fecha: {fecha}'),
                  p(f"Cliente: {venta.get('cliente_nombre') or 'Consumidor final'}"),
                  p(f"Atendido por: {venta.get('empleado') or 'Personal del comercio'}"),
                  p(f"Forma de pago: {str(venta.get('metodo_pago') or 'efectivo').capitalize()}"), Spacer(1, 16)]
    filas = [[p('Producto', cabecera), p('Unidades', cabecera), p('Precio unit.', cabecera), p('Importe', cabecera)]]
    for item in productos:
        nombre = item.get('producto') or item.get('nombre_producto') or 'Producto'
        if item.get('codigo_barras'):
            nombre += '\nCódigo: ' + str(item['codigo_barras'])
        filas.append([p(nombre), p(item['cantidad'], derecha), p(importe(item['precio_unitario']), derecha),
                      p(importe(item['subtotal']), derecha)])
    tabla = Table(filas, colWidths=[ancho - 244, 64, 90, 90], repeatRows=1, hAlign='LEFT')
    tabla.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), azul),
                               ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, gris]),
                               ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                               ('TOPPADDING', (0, 0), (-1, -1), 9),
                               ('BOTTOMPADDING', (0, 0), (-1, -1), 9)]))
    contenido.append(tabla)
    resumen = []
    for etiqueta, valor in [('Subtotal', venta['subtotal']), ('Descuento', venta.get('descuento', 0)),
                            ('TOTAL PAGADO', venta['total'])]:
        estilo = total_estilo if etiqueta == 'TOTAL PAGADO' else derecha
        resumen.append([p(etiqueta, estilo), p(importe(valor), estilo)])
    if venta.get('monto_recibido') is not None:
        resumen.append([p('Efectivo recibido', derecha), p(importe(venta['monto_recibido']), derecha)])
        resumen.append([p('Vuelto entregado', derecha), p(importe(venta.get('cambio', 0)), derecha)])
    tabla_total = Table(resumen, colWidths=[ancho - 140, 140])
    tabla_total.setStyle(TableStyle([('TOPPADDING', (0, 0), (-1, -1), 5),
                                     ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                                     ('LINEABOVE', (0, 2), (-1, 2), 1, naranja)]))
    contenido.append(KeepTogether([Spacer(1, 16), tabla_total, Spacer(1, 20),
                                  p('Gracias por su compra. Conserve este comprobante.')] ))

    def pie(canvas, documento):
        canvas.saveState()
        canvas.setFont('STRegular', 8)
        canvas.setFillColor(azul)
        canvas.drawString(36, 24, 'StockTrust | Comprobante de compra')
        canvas.drawRightString(A4[0] - 36, 24, f'Página {documento.page}')
        canvas.restoreState()

    doc.build(contenido, onFirstPage=pie, onLaterPages=pie)
    return salida.getvalue()
