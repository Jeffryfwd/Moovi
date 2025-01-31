from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
import re
import json
from PIL import Image
import pytesseract
import fitz  # PyMuPDF para manejar PDFs
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import pickle
from googleapiclient.http import MediaInMemoryUpload
from google.auth.transport.requests import Request
import os

# Configuración Tesseract
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

# Alcances para Google Docs y Drive
SCOPES = ['https://www.googleapis.com/auth/drive.file', 'https://www.googleapis.com/auth/documents']

class LeerArchivoPdf(APIView):
    parser_classes = (MultiPartParser, FormParser)

    def limpiar_texto(self, texto):
        return texto.replace('\n', ' ').replace('  ', ' ').replace('(', '').replace(')', '').replace('_', '').strip()

    def extraer_datos(self, texto):
        # Patrones mejorados para ser más flexibles
        solicitado_nombre_pattern = r"Solicitado\s*por[:\s]*Nombre[:\s]*([\w\s'/-]+)"
        solicitado_telefono_pattern = r"Tel[eé]fono[:\s]*([\d\s\(\)\-]+)"
        solicitado_correo_pattern = r"Correo[:\s]*([\w.\-_]+@[A-Za-z0-9\.\-]+\.[A-Za-z]{2,})"

        # Patrones para "Entregar a"
        entregar_nombre_pattern = r"Entregar\s*a[:\s]*Nombre[:\s]*([\w\s'/-]+)"
        entregar_telefono_pattern = r"Tel[eé]fono[:\s]*([\d\s\(\)\-]+)"
        entregar_direccion_pattern = r"Direcci[oó]n[:\s]*([\w\s,.\-]+)"
        entregar_notas_pattern = r"Notas[:\s]*([\w\s'/,.\-]*)"

        # Extraer valores con validación
        def obtener_valor(pattern):
            match = re.search(pattern, texto)
            return match.group(1).strip() if match else "No disponible"

        datos = {
            "Solicitado_por": {
                "Nombre": obtener_valor(solicitado_nombre_pattern),
                "Teléfono": obtener_valor(solicitado_telefono_pattern),
                "Correo": obtener_valor(solicitado_correo_pattern)
            },
            "Entregar_a": {
                "Nombre": obtener_valor(entregar_nombre_pattern),
                "Teléfono": obtener_valor(entregar_telefono_pattern),
                "Dirección": obtener_valor(entregar_direccion_pattern),
                "Notas": obtener_valor(entregar_notas_pattern)
            }
        }
        
        return datos
    
    
    def procesar_pdf(self, pdf_file):
        pdf_documento = fitz.open(stream=pdf_file.read(), filetype="pdf")
        resultados = []

        for num_pagina in range(len(pdf_documento)):
            pagina = pdf_documento[num_pagina]

            for img_index, img in enumerate(pagina.get_images(full=True)):
                xref = img[0]
                base_img = pdf_documento.extract_image(xref)
                image_bytes = base_img["image"]
                image_ext = base_img["ext"]
                image_path = f"temp_image_pagina_{num_pagina + 1}_img_{img_index + 1}.{image_ext}"

                with open(image_path, "wb") as img_file:
                    img_file.write(image_bytes)

                img = Image.open(image_path)
                texto_extraido = pytesseract.image_to_string(img, lang="spa")
                texto_limpio = self.limpiar_texto(texto_extraido)

                datos = self.extraer_datos(texto_limpio)
                resultados.append({
                    "Pagina": num_pagina + 1,
                    "Imagen": img_index + 1,
                    "Datos": datos
                })
        
        return resultados
                

    def post(self, request, *args, **kwargs):
        pdf_file = request.FILES.get('archivo_pdf')

        if not pdf_file:
            return Response({"error": "No se ha proporcionado ningún archivo PDF"}, status=400)

        try:
            print("\u2705 Archivo PDF recibido")
            resultados = self.procesar_pdf(pdf_file)
            print(f"\u2705 Resultados extraídos: {resultados}")

            texto_extraido = formatear_datos_limpios(resultados)

            creds = cargar_credenciales()
            print("\u2705 Credenciales cargadas correctamente")

            document_id = crear_documento_google(creds, texto_extraido)
            if document_id:
                print(f'Documento creado con ID: {document_id}')

            file_id = subir_archivo_drive(creds, texto_extraido)
            if file_id:
                print(f'Archivo subido con ID: {file_id}')

            return Response(resultados, status=200)

        except Exception as e:
            return Response({"error": f"Error al procesar el archivo PDF: {str(e)}"}, status=500)


def cargar_credenciales():
    creds = None
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                "../Backend/api/google_credentials/credentials.json", SCOPES)
            creds = flow.run_local_server(port=5173)

        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)

    return creds


def crear_documento_google(creds, texto):
    try:
        service = build('docs', 'v1', credentials=creds)
        document = service.documents().create().execute()
        document_id = document['documentId']

        requests = [{'insertText': {'location': {'index': 1}, 'text': texto}}]
        service.documents().batchUpdate(documentId=document_id, body={'requests': requests}).execute()
        return document_id
    except HttpError as err:
        print(f"Error al crear el documento: {err}")
        return None


def subir_archivo_drive(creds, texto, nombre_archivo="documento_extraido.txt"):
    try:
        service = build('drive', 'v3', credentials=creds)
        file_metadata = {'name': nombre_archivo, 'mimeType': 'text/plain'}
        media = MediaInMemoryUpload(texto.encode(), mimetype='text/plain')

        file = service.files().create(
            media_body=media, body=file_metadata, fields='id'
        ).execute()

        return file.get('id')
    except HttpError as err:
        print(f"Error al subir archivo: {err}")
        return None
def formatear_datos_limpios(datos):
    texto_limpio = ""
    for res in datos:
        datos_res = res.get("Datos", {})
        solicitado = datos_res.get("Solicitado_por", {})
        entregar = datos_res.get("Entregar_a", {})

        texto_limpio += (
            f"--- Página {res.get('Pagina', '?')} Imagen {res.get('Imagen', '?')} ---\n"
            f"Solicitado por:\n"
            f"  Nombre: {solicitado.get('Nombre', 'No disponible')}\n"
            f"  Teléfono: {solicitado.get('Teléfono', 'No disponible')}\n"
            f"  Correo: {solicitado.get('Correo', 'No disponible')}\n\n"
            f"Entregar a:\n"
            f"  Nombre: {entregar.get('Nombre', 'No disponible')}\n"
            f"  Teléfono: {entregar.get('Teléfono', 'No disponible')}\n"
            f"  Dirección: {entregar.get('Dirección', 'No disponible')}\n"
            f"  Notas: {entregar.get('Notas', 'No disponible')}\n"
        )
        texto_limpio += "\n" + "-" * 40 + "\n"

    return texto_limpio.strip()
    