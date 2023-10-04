# HuntLG

# Documentación de HuntLG - Herramienta de Threat Hunting

# Descripción

HuntLG es una herramienta de Threat Hunting creada por Christian López. Esta herramienta permite a los analistas de seguridad buscar amenazas en registros de eventos de Windows y archivos de registro, identificar malware, generar informes en formato PDF, exportar resultados a CSV, enviar informes por correo electrónico, aislar archivos sospechosos y aislar equipos en la misma red, todo a través de una interfaz gráfica de usuario (GUI).

# Funcionalidades Principales

Búsqueda y Análisis de Malware: HuntLG permite buscar patrones y malware en archivos de registro de eventos de Windows y otros archivos de registro.

Generación de Informes: Puede generar informes en formato PDF que incluyen los resultados de análisis y detalles de los archivos sospechosos encontrados.

Exportación a CSV: Puede exportar los resultados de análisis a un archivo CSV para un análisis adicional o informes personalizados.

Envío de Informes por Correo Electrónico: HuntLG le permite enviar automáticamente informes por correo electrónico a destinatarios específicos.

Aislamiento de Archivos Sospechosos: Puede aislar archivos sospechosos en una carpeta de cuarentena para su posterior análisis o eliminación.

Aislamiento de Equipos en la Red: HuntLG le permite aislar equipos en la misma red utilizando comandos personalizables.

# Requisitos Previos

Python 3 instalado en su sistema.
La biblioteca YARA instalada (pip install yara-python).
Las bibliotecas tkinter, pandas y reportlab instaladas (pip install tk pandas reportlab).

# Uso de HuntLG

# Descarga de Código Fuente:
Descargue el código fuente de HuntLG desde el repositorio en GitHub.

# Configuración de Reglas YARA:

Edite el archivo malware_rules.yar y agregue sus reglas YARA personalizadas.
# Configuración de Carpetas:

Defina la ruta de la carpeta de cuarentena (CARPETA_CUARENTENA) en el código.

# Ejecución de la Aplicación:

Ejecute HuntLG.py para abrir la interfaz gráfica de usuario (GUI) de HuntLG.

# Búsqueda y Análisis de Malware:

Ingrese los patrones de búsqueda en el campo "Patrones" (separados por coma).
Ingrese una fecha límite en el formato "YYYY-MM-DD HH:MM:SS" en el campo "Fecha Límite".
Haga clic en el botón "Buscar y Analizar Malware" para iniciar la búsqueda y análisis de malware en los archivos de registro.
Generación de Informes:

Una vez completada la búsqueda, se generará un informe en formato PDF automáticamente.
Puede hacer clic en el botón "Enviar Informe por Correo" para enviar el informe por correo electrónico si es necesario.
Aislamiento de Archivos Sospechosos:

Puede hacer clic en el botón "Aislar Archivos Sospechosos" para mover archivos sospechosos a la carpeta de cuarentena.
Aislamiento de Equipos en la Red:

Ingrese la dirección IP del equipo que desea aislar en el campo "Dirección IP a aislar".
Haga clic en el botón "Aislar Equipo en la Red" para ejecutar el comando de aislamiento (asegúrese de que el comando sea adecuado para su red).
Exportación de Resultados a CSV:

Los resultados de la búsqueda se exportarán automáticamente a un archivo CSV llamado resultados_threat_hunting.csv.

# Notas Adicionales
HuntLG puede ser personalizado y ampliado según sus necesidades específicas.
Asegúrese de configurar adecuadamente la autenticación de correo electrónico si planea utilizar la función de envío de informes por correo electrónico.

# ¡HuntLG está listo para ayudarte en la búsqueda de amenazas y la respuesta a incidentes!
