import os
import re
import datetime
import yara
import csv
import pandas as pd
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from tkinter import filedialog
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import subprocess

# Nombre del creador
CREADOR = "Christian López"

# Ruta al archivo que contiene las reglas YARA
ARCHIVO_REGLAS = 'ruta/a/tu/archivo/malware_rules.yar'

# Ruta a la carpeta de cuarentena
CARPETA_CUARENTENA = 'cuarentena'

# Cargar reglas YARA con firmas de malware
try:
    reglas_malware = yara.compile(filepath=ARCHIVO_REGLAS)
except Exception as e:
    messagebox.showerror("Error", f"Error al cargar las reglas YARA: {str(e)}")
    exit()

# Función para buscar malware en un archivo de registro
def buscar_malware_en_archivo(archivo_path):
    with open(archivo_path, 'r', encoding='utf-8', errors='ignore') as archivo:
        contenido = archivo.read()
        matches = reglas_malware.match(data=contenido)
        if matches:
            return [match.rule for match in matches]

# Función para buscar patrones en los archivos de registro
def buscar_patrones_en_archivos(directorio, patrones, fecha_limite=None):
    resultados = []

    for root, _, files in os.walk(directorio):
        for filename in files:
            archivo_path = os.path.join(root, filename)
            with open(archivo_path, 'r', encoding='utf-8', errors='ignore') as archivo:
                for line in archivo:
                    for patron in patrones:
                        if re.search(patron, line, re.IGNORECASE):
                            timestamp = os.path.getctime(archivo_path)
                            fecha_registro = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                            resultados.append({
                                'Archivo': archivo_path,
                                'Patron': patron,
                                'Linea': line.strip(),
                                'Fecha': fecha_registro
                            })

    return resultados

# Función para exportar resultados a un archivo CSV
def exportar_a_csv(resultados, archivo_salida):
    try:
        df = pd.DataFrame(resultados)
        df.to_csv(archivo_salida, index=False, encoding='utf-8')
        messagebox.showinfo("Éxito", f"Resultados exportados a {archivo_salida}")
    except Exception as e:
        messagebox.showerror("Error", f"Error al exportar a CSV: {str(e)}")

# Función para generar un informe en formato PDF
def generar_informe_pdf(resultados):
    try:
        pdf_file = "informe_threat_hunting.pdf"
        c = canvas.Canvas(pdf_file, pagesize=letter)
        c.drawString(100, 750, "Informe de Threat Hunting")
        c.drawString(100, 730, "Resultados de Análisis")
        c.drawString(100, 710, "=" * 50)
        y = 690

        for resultado in resultados:
            c.drawString(100, y, f"Archivo: {resultado['Archivo']}")
            c.drawString(100, y - 15, f"Patrón: {resultado['Patron']}")
            c.drawString(100, y - 30, f"Línea: {resultado['Linea']}")
            c.drawString(100, y - 45, f"Fecha: {resultado['Fecha']}")
            c.drawString(100, y - 60, "=" * 50)
            y -= 80

        c.save()
        messagebox.showinfo("Informe PDF", f"Informe PDF generado: {pdf_file}")
    except Exception as e:
        messagebox.showerror("Error", f"Error al generar el informe PDF: {str(e)}")

# Función para enviar el informe por correo electrónico
def enviar_informe_por_correo(resultados):
    try:
        # Configurar el servidor SMTP y las credenciales
        smtp_server = 'smtp.example.com'
        smtp_port = 587
        correo_emisor = 'tu_correo@example.com'
        contraseña_emisor = 'tu_contraseña'
        correo_destinatario = 'destinatario@example.com'

        # Crear el mensaje de correo
        mensaje = MIMEMultipart()
        mensaje['From'] = correo_emisor
        mensaje['To'] = correo_destinatario
        mensaje['Subject'] = 'Informe de Threat Hunting'

        # Cuerpo del mensaje
        cuerpo_mensaje = """
        Adjunto encontrarás el informe de Threat Hunting con los resultados del análisis.
        """
        mensaje.attach(MIMEText(cuerpo_mensaje, 'plain'))

        # Adjuntar el informe PDF al mensaje
        pdf_file = "informe_threat_hunting.pdf"
        with open(pdf_file, 'rb') as archivo_pdf:
            adjunto = MIMEApplication(archivo_pdf.read(), _subtype="pdf")
            adjunto.add_header('Content-Disposition', f'attachment; filename="{pdf_file}"')
            mensaje.attach(adjunto)

        # Conectar y enviar el correo
        servidor_smtp = smtplib.SMTP(smtp_server, smtp_port)
        servidor_smtp.starttls()
        servidor_smtp.login(correo_emisor, contraseña_emisor)
        servidor_smtp.sendmail(correo_emisor, correo_destinatario, mensaje.as_string())
        servidor_smtp.quit()

        messagebox.showinfo("Correo Electrónico", "Informe enviado por correo electrónico.")
    except Exception as e:
        messagebox.showerror("Error", f"Error al enviar el correo electrónico: {str(e)}")

# Función para manejar la opción de envío de informe por correo
def enviar_informe_opcion():
    enviar_informe = messagebox.askyesno("Enviar Informe por Correo", "¿Desea enviar el informe por correo electrónico?")
    if enviar_informe:
        enviar_informe_por_correo(resultados_threat_hunting)

# Función para buscar y analizar malware
def buscar_y_analizar_malware():
    global resultados_threat_hunting

    directorio_registros = filedialog.askdirectory(title="Seleccionar Directorio de Registros")
    if not directorio_registros:
        return

    patrones = entrada_patrones.get().split(',')
    fecha_limite = fecha_limite_entry.get()
    if not fecha_limite:
        messagebox.showerror("Error", "Debes ingresar una fecha límite.")
        return

    resultados = buscar_patrones_en_archivos(directorio_registros, patrones, fecha_limite)
    resultados_filtrados = []

    for resultado in resultados:
        resultado['Malware'] = buscar_malware_en_archivo(resultado['Archivo'])
        if resultado['Malware']:
            resultados_filtrados.append(resultado)

    if resultados_filtrados:
        exportar_a_csv(resultados_filtrados, 'resultados_threat_hunting.csv')
        generar_informe_pdf(resultados_filtrados)
        enviar_informe_opcion()
        resultados_threat_hunting = resultados_filtrados
        aislamiento_opcion()
    else:
        messagebox.showinfo("Información", "No se encontraron resultados.")
        resultados_threat_hunting = []

# Función para aislar archivos sospechosos
def aislamiento_opcion():
    aislamiento = messagebox.askyesno("Aislar Archivos Sospechosos", "¿Desea aislar archivos sospechosos en cuarentena?")
    if aislamiento:
        cuarentenar_archivos(resultados_threat_hunting)

# Función para cuarentenar archivos sospechosos
def cuarentenar_archivos(resultados):
    try:
        if not os.path.exists(CARPETA_CUARENTENA):
            os.mkdir(CARPETA_CUARENTENA)

        for resultado in resultados:
            archivo_origen = resultado['Archivo']
            archivo_destino = os.path.join(CARPETA_CUARENTENA, os.path.basename(archivo_origen))
            os.rename(archivo_origen, archivo_destino)

        messagebox.showinfo("Cuarentena", f"Archivos sospechosos aislados en: {CARPETA_CUARENTENA}")
    except Exception as e:
        messagebox.showerror("Error", f"Error al cuarentenar archivos: {str(e)}")

# Función para aislar un equipo en la red
def aislar_equipo():
    direccion_ip = direccion_ip_entry.get()
    if not direccion_ip:
        messagebox.showerror("Error", "Debes ingresar la dirección IP del equipo a aislar.")
        return

    try:
        # Ejecutar comando de aislamiento (esto puede variar según tu red y sistema operativo)
        comando = f"iptables -A INPUT -s {direccion_ip} -j DROP"
        subprocess.run(comando, shell=True, check=True)

        messagebox.showinfo("Aislamiento Exitoso", f"El equipo {direccion_ip} ha sido aislado en la red.")
    except Exception as e:
        messagebox.showerror("Error", f"Error al aislar el equipo: {str(e)}")

# Crear la ventana principal
ventana = tk.Tk()
ventana.title("HuntLG - Herramienta de Threat Hunting")
ventana.geometry("400x600")

# Crear etiquetas y campos de entrada
etiqueta_patrones = ttk.Label(ventana, text="Patrones (separados por coma):")
etiqueta_fecha_limite = ttk.Label(ventana, text="Fecha Límite (YYYY-MM-DD HH:MM:SS):")
entrada_patrones = ttk.Entry(ventana)
fecha_limite_entry = ttk.Entry(ventana)

# Crear botón de búsqueda y análisis
boton_buscar = ttk.Button(ventana, text="Buscar y Analizar Malware", command=buscar_y_analizar_malware)

# Crear botón para seleccionar el directorio de registros
def seleccionar_directorio():
    global directorio_registros
    directorio_registros = filedialog.askdirectory(title="Seleccionar Directorio de Registros")
    if directorio_registros:
        directorio_label.config(text=directorio_registros)

boton_seleccionar_directorio = ttk.Button(ventana, text="Seleccionar Directorio", command=seleccionar_directorio)

# Etiqueta para mostrar el directorio seleccionado
directorio_label = ttk.Label(ventana, text="Directorio de Registros: No seleccionado")

# Crear opción para enviar informe por correo
enviar_correo_var = tk.IntVar()
opcion_enviar_correo = ttk.Checkbutton(ventana, text="Enviar Informe por Correo", variable=enviar_correo_var)

# Crear botón para aislar archivos sospechosos
boton_aislar = ttk.Button(ventana, text="Aislar Archivos Sospechosos", command=aislamiento_opcion)

# Crear etiqueta y campo de entrada para la dirección IP a aislar
etiqueta_ip = ttk.Label(ventana, text="Dirección IP a aislar:")
direccion_ip_entry = ttk.Entry(ventana)

# Crear botón para aislar equipo en la red
boton_aislar_equipo = ttk.Button(ventana, text="Aislar Equipo en la Red", command=aislar_equipo)

# Colocar elementos en la ventana
etiqueta_patrones.pack(padx=10, pady=5, anchor="w")
entrada_patrones.pack(padx=10, pady=5)
etiqueta_fecha_limite.pack(padx=10, pady=5, anchor="w")
fecha_limite_entry.pack(padx=10, pady=5)
boton_seleccionar_directorio.pack(padx=10, pady=5)
directorio_label.pack(padx=10, pady=5)
opcion_enviar_correo.pack(padx=10, pady=5)
boton_buscar.pack(padx=10, pady=10)
boton_aislar.pack(padx=10, pady=10)
etiqueta_ip.pack(padx=10, pady=5, anchor="w")
direccion_ip_entry.pack(padx=10, pady=5)
boton_aislar_equipo.pack(padx=10, pady=10)

# Mostrar información del creador
messagebox.showinfo("Acerca de HuntLG", f"HuntLG - Herramienta de Threat Hunting\nCreado por {CREADOR}")

# Variable para almacenar los resultados
resultados_threat_hunting = []

# Ejecutar la ventana principal
ventana.mainloop()
