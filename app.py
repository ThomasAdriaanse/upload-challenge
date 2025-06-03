#!/usr/bin/env python3
"""
app.py  –  Runnable skeleton for a *secure* image-uploader web service.

 ▶  This version eliminates the TemplateNotFound 500 error by registering
    the inline Jinja templates with a DictLoader, so {% extends "BASE" %}
    now resolves correctly.

 ▶  All security features have been implemented.

Start:  python app.py
Browse: http://localhost:8080/
"""

import os
import magic
from pathlib import Path
from werkzeug.utils import secure_filename
from markupsafe import escape
from flask import (
    Flask, request, abort, render_template, send_from_directory, url_for,
    Response
)
from jinja2 import ChoiceLoader, DictLoader

# ─────────────────────────── Configuration ────────────────────────────
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
ALLOWED_MIMETYPES = {"image/png", "image/jpeg", "image/gif"}
MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB

app = Flask(__name__)
app.config.update(
    UPLOAD_FOLDER=UPLOAD_FOLDER,
    MAX_CONTENT_LENGTH=MAX_CONTENT_LENGTH,
)

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ───────────────────────── Inline templates ───────────────────────────
BASE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Simple Secure Uploader</title>
    <!-- Bootstrap 5 CDN -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  </head>
  <body class="bg-light">
    <nav class="navbar navbar-dark bg-dark px-3">
      <a class="navbar-brand" href="{{ url_for('upload') }}">Uploader</a>
      <a class="btn btn-outline-light btn-sm" href="{{ url_for('list_files') }}">Files</a>
    </nav>
    <main class="container py-4">
      {% block body %}{% endblock %}
    </main>
  </body>
</html>
"""

UPLOAD_FORM = """
{% extends "BASE" %}
{% block body %}
  <h1 class="mb-4">Upload an Image</h1>
  <form class="card card-body" method="post" enctype="multipart/form-data">
    <div class="mb-3">
      <input class="form-control" type="file" name="file" required>
    </div>
    <button class="btn btn-primary" type="submit">Upload</button>
  </form>
{% if message %}
  <div class="alert alert-warning mt-4">{{ message }}</div>
{% endif %}
{% endblock %}
"""

FILE_LIST = """
{% extends "BASE" %}
{% block body %}
  <h1 class="mb-4">Uploaded Files</h1>
  {% if files %}
    <ul class="list-group">
      {% for f in files %}
        <li class="list-group-item d-flex justify-content-between align-items-center">
          <span>{{ f }}</span>
          <a class="btn btn-sm btn-secondary" href="{{ url_for('serve_file', filename=f) }}">Download</a>
        </li>
      {% endfor %}
    </ul>
  {% else %}
    <p class="text-muted">No files uploaded yet.</p>
  {% endif %}
{% endblock %}
"""

# Register our in-memory templates so {% extends "BASE" %} works
TEMPLATES = {
    "BASE": BASE,
    "UPLOAD_FORM": UPLOAD_FORM,
    "FILE_LIST": FILE_LIST,
}

app.jinja_loader = ChoiceLoader([
    app.jinja_loader,          # keep default filesystem loader
    DictLoader(TEMPLATES),     # add our dict
])

# Tiny helper so routes can call render("UPLOAD_FORM", message=...)
render = lambda name, **ctx: render_template(name, **ctx)  # noqa: E731

def allowed_file(filename):
    """Check if the file has an allowed extension."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_image(stream):
    """Validate that the file is actually an image using magic numbers."""
    # Read the first few bytes to check the file signature
    header = stream.read(2048)
    stream.seek(0)
    
    # Use python-magic to detect the MIME type
    mime = magic.Magic(mime=True)
    mime_type = mime.from_buffer(header)
    
    if not mime_type or mime_type not in ALLOWED_MIMETYPES:
        return None
        
    # Map MIME types to extensions
    extension_map = {
        'image/jpeg': '.jpg',
        'image/png': '.png',
        'image/gif': '.gif'
    }
    
    return extension_map.get(mime_type)

# ───────────────────────────── Routes ────────────────────────────────
@app.route("/", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        # Check if a file was actually submitted
        if 'file' not in request.files:
            return render("UPLOAD_FORM", message="No file selected")
        
        file = request.files['file']
        if file.filename == '':
            return render("UPLOAD_FORM", message="No file selected")

        if file and allowed_file(file.filename):
            # Secure the filename and create full path
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            # Validate that it's actually an image
            extension = validate_image(file.stream)
            if not extension:
                return render("UPLOAD_FORM", message="Invalid image file")
            
            # Save the file
            try:
                file.save(filepath)
                return render("UPLOAD_FORM", message=f"Successfully uploaded {escape(filename)}")
            except Exception as e:
                app.logger.error(f"Upload failed: {e}")
                return render("UPLOAD_FORM", message="Upload failed"), 500
        else:
            return render("UPLOAD_FORM", message="Invalid file type. Allowed types: " + ", ".join(ALLOWED_EXTENSIONS))
    
    return render("UPLOAD_FORM", message=None)

@app.route("/files/")
def list_files():
    try:
        # Get all files in upload directory
        files = []
        for f in sorted(os.listdir(app.config['UPLOAD_FOLDER'])):
            if os.path.isfile(os.path.join(app.config['UPLOAD_FOLDER'], f)):
                files.append(escape(f))
        return render("FILE_LIST", files=files)
    except Exception as e:
        app.logger.error(f"File listing failed: {e}")
        abort(500)

@app.route("/files/<path:filename>")
def serve_file(filename):
    # Validate the filename is secure and within UPLOAD_FOLDER
    try:
        safe_path = Path(app.config['UPLOAD_FOLDER']) / secure_filename(filename)
        safe_path = safe_path.resolve()
        upload_path = Path(app.config['UPLOAD_FOLDER']).resolve()
        
        if not safe_path.is_file() or upload_path not in safe_path.parents:
            abort(404)
        
        response = send_from_directory(
            app.config['UPLOAD_FOLDER'],
            filename,
            as_attachment=True
        )
        
        # Add security headers
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response
    
    except Exception as e:
        app.logger.error(f"File serving failed: {e}")
        abort(404)

# ─────────────────────────── Main entry ──────────────────────────────
if __name__ == "__main__":
    # For live debugging you can set debug=True
    app.run(port=8080, debug=False)
