# Local LLM Phishing Analyzer

A Streamlit app that parses pasted email text or `.eml` files, extracts common email headers and HTTP/HTTPS URLs, performs a few transparent local checks, and asks an Ollama model for a plain-language report in English or Spanish.

## 1. Install Python

Use Python 3.10 or newer. Verify:

    python --version

## 2. Install Ollama

Download and install Ollama from:

https://ollama.com/download

Start Ollama. On Windows and macOS, the desktop app normally starts the local service. On Linux, you can start it with:

    ollama serve

Keep Ollama running while using the app.

## 3. Download a model

For a modest local model, run:

    ollama pull llama3.2

You can use another model you have downloaded; enter its exact name in the app's **Ollama model** field. To see installed models:

    ollama list

The default local Ollama endpoint is `http://localhost:11434`.

## 4. Install and run the Streamlit app

Open a terminal in this project folder:

    python -m venv .venv

Activate it:

**Windows PowerShell**
    .venv\Scripts\Activate.ps1

**macOS / Linux**
    source .venv/bin/activate

Install dependencies and launch:

    pip install -r requirements.txt
    streamlit run app.py

Streamlit will print a local browser address, usually `http://localhost:8501`.

## 5. Use it

1. Choose English or Español in the sidebar.
2. Paste a complete email (including headers), or upload an `.eml` file.
3. Confirm the Ollama URL is `http://localhost:11434`.
4. Enter the model name, normally `llama3.2`.
5. Click **Analyze email / Analizar correo**.

## Privacy and safety notes

- The app does not visit or resolve extracted URLs.
- For local-only processing, keep the Ollama URL pointed at `localhost` or `127.0.0.1`. If you enter a remote server, the email content is sent to that server.
- The model receives email text as untrusted data. The prompt tells it not to follow instructions embedded in the email, but prompt injection defenses are not perfect.
- This is a triage aid, not a malware sandbox, email-authentication verifier, or guarantee of safety.
- The current version extracts plain-text body content and selected headers. It does not download or execute attachments, render HTML, or follow links.
- Avoid uploading confidential email to a machine or Ollama server you do not control.

## Project files

- `app.py` — Streamlit application.
- `requirements.txt` — Python dependencies.
- `README.md` — setup and usage guide.
