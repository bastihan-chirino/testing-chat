# Chatbot IA

Guía rápida para preparar y ejecutar la app desde esta carpeta:

```powershell
cd "C:\Users\bcf19\Desktop\Nueva carpeta\experimento_chat"
```

## Preparar el ambiente

Crear y activar el entorno virtual:

```powershell
py -3 -m venv venv
.\venv\Scripts\activate
```

Es necesario crear una variable de entorno llamada GEMINI_API_KEY para que funcione.

Instalar dependencias:

```powershell
python -m pip install --upgrade pip
python -m pip install streamlit google-genai PyPDF2 python-docx presidio-analyzer
```

Se utiliza para disponibilizar la url a navegadores.

```powershell
ngrok http PORT
```

## Ejecutar la aplicación

Modo normal:

```powershell
python -m streamlit run "content\chatbot.py" --server.headless true --server.port 8501
```

Con subida de documentos:

```powershell
python -m streamlit run "content\chatbot.py" --server.headless true --server.port 8501 -- --enable-document-upload
```

Sin advertencias emergentes de PII:

```powershell
python -m streamlit run "content\chatbot.py" --server.headless true --server.port 8501 -- --disable-pii-warnings
```

Con subida de documentos y sin advertencias emergentes de PII:

```powershell
python -m streamlit run "content\chatbot.py" --server.headless true --server.port 8501 -- --enable-document-upload --disable-pii-warnings
```

Abrir en el navegador:

```text
http://localhost:8501
```

## Ejecutar pruebas

```powershell
python -m unittest discover -s tests -v
```
