from flask import render_template, request, flash, send_file, jsonify, url_for
from . import web_ui_bp
from .forms import TextEncryptionForm, FileEncryptionForm
from app.crypto_utils import (
    encrypt_text, decrypt_text,
    encrypt_file_with_password, decrypt_file_with_password,
    derive_key_from_password
)
import io

TEXT_SALT = b'a_fixed_salt_for_web_demo_'

@web_ui_bp.route('/')
def index():
    return render_template("index.html")

@web_ui_bp.route('/text', methods=['GET', 'POST'])
def text_encryption():
    form = TextEncryptionForm()
    if request.method == 'POST':
        if not form.validate_on_submit():
            return jsonify({'success': False, 'message': 'Invalid form submission.'})

        action = request.form.get('action')
        key = derive_key_from_password(form.password.data, TEXT_SALT)

        try:
            if action == 'encrypt':
                encrypted_text = encrypt_text(form.text_input.data, key)
                return jsonify({'success': True, 'data': encrypted_text, 'message': 'Text successfully encrypted!'})
            elif action == 'decrypt':
                decrypted_text = decrypt_text(form.text_input.data, key)
                return jsonify({'success': True, 'data': decrypted_text, 'message': 'Text successfully decrypted!'})
        except Exception as e:
            return jsonify({'success': False, 'message': f'Operation failed: {e}'})

    return render_template("text_encryption.html", form=form)

@web_ui_bp.route('/file', methods=['GET', 'POST'])
def file_encryption():
    form = FileEncryptionForm()
    if form.validate_on_submit():
        file = form.file_upload.data
        password = form.password.data
        action = request.form.get('action')

        try:
            if action == 'encrypt':
                encrypted_file = io.BytesIO()
                encrypt_file_with_password(file.stream, password, encrypted_file)
                encrypted_file.seek(0)
                return send_file(
                    encrypted_file,
                    as_attachment=True,
                    download_name=f"{file.filename}.enc",
                    mimetype='application/octet-stream'
                )
            elif action == 'decrypt':
                decrypted_file = io.BytesIO()
                decrypt_file_with_password(file.stream, password, decrypted_file)
                decrypted_file.seek(0)
                original_filename = file.filename.rsplit('.enc', 1)[0] if file.filename.endswith('.enc') else f"{file.filename}.dec"
                return send_file(
                    decrypted_file,
                    as_attachment=True,
                    download_name=original_filename,
                    mimetype='application/octet-stream'
                )
        except Exception as e:
            flash(f'File operation failed: {e}', 'danger')
    
    return render_template("file_encryption.html", form=form)