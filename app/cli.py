import click
import os
from flask.cli import with_appcontext
from .crypto_utils import (
    encrypt_text, decrypt_text, 
    encrypt_file, decrypt_file,
    encrypt_file_with_password, decrypt_file_with_password,
    encrypt_folder, decrypt_folder,
    encrypt_folder_with_password, decrypt_folder_with_password,
    caesar_cipher, load_key, generate_key, derive_key_from_password
)

@click.group()
def encryptor():
    """A CLI for encrypting and decrypting files and text."""
    pass

# --- Text Encryption/Decryption Commands ---

@encryptor.command("encrypt-text")
@click.argument('text')
@click.option('--key', help='The encryption key. If not provided, uses secret.key.')
@click.option('--password', help='A password to derive the encryption key.')
def encrypt_text_cli(text, key, password):
    if password:
        salt = b'salt_for_text_' # Not secure for production
        key = derive_key_from_password(password, salt)
        click.echo("Warning: Encrypting text with a password uses a fixed salt. Use file encryption for better security.")
    elif not key:
        try:
            key = load_key()
        except FileNotFoundError:
            click.echo("Error: secret.key not found. Please generate one with 'flask encryptor generate-key' or provide a key/password.")
            return
    else:
        key = key.encode()
    
    encrypted_text = encrypt_text(text, key)
    click.echo(encrypted_text)

@encryptor.command("decrypt-text")
@click.argument('text')
@click.option('--key', help='The decryption key.')
@click.option('--password', help='A password to derive the decryption key.')
def decrypt_text_cli(text, key, password):
    if password:
        salt = b'salt_for_text_' # Must match the salt used in encryption
        key = derive_key_from_password(password, salt)
    elif not key:
        try:
            key = load_key()
        except FileNotFoundError:
            click.echo("Error: secret.key not found. Please provide a key/password.")
            return
    else:
        key = key.encode()

    try:
        decrypted_text = decrypt_text(text, key)
        click.echo(decrypted_text)
    except Exception as e:
        click.echo(f"Decryption failed. Error: {e}")

# --- File Encryption/Decryption Commands ---

@encryptor.command("encrypt-file")
@click.argument('file_path', type=click.Path(exists=True, dir_okay=False))
@click.option('--key', help='The encryption key.')
@click.option('--password', help='A password for encryption.')
def encrypt_file_cli(file_path, key, password):
    if password:
        output_path = file_path + ".enc"
        try:
            with open(file_path, "rb") as in_f, open(output_path, "wb") as out_f:
                encrypt_file_with_password(in_f, password, out_f)
            click.echo(f"File encrypted successfully to {output_path}")
        except Exception as e:
            click.echo(f"File encryption failed: {e}")
        return

    if not key:
        try:
            key = load_key()
        except FileNotFoundError:
            click.echo("Error: No key provided and secret.key not found.")
            return
    else:
        key = key.encode()

    try:
        encrypt_file(file_path, key)
        click.echo(f"File encrypted successfully to {file_path}.enc")
    except Exception as e:
        click.echo(f"Encryption failed: {e}")


@encryptor.command("decrypt-file")
@click.argument('file_path', type=click.Path(exists=True, dir_okay=False))
@click.option('--key', help='The decryption key.')
@click.option('--password', help='A password for decryption.')
def decrypt_file_cli(file_path, key, password):
    if password:
        output_path = os.path.splitext(file_path)[0]
        try:
            with open(file_path, "rb") as in_f, open(output_path, "wb") as out_f:
                decrypt_file_with_password(in_f, password, out_f)
            click.echo(f"File decrypted successfully to {output_path}")
        except Exception as e:
            click.echo(f"File decryption failed. Check password or file integrity. Error: {e}")
        return

    if not key:
        try:
            key = load_key()
        except FileNotFoundError:
            click.echo("Error: No key provided and secret.key not found.")
            return
    else:
        key = key.encode()
    
    try:
        decrypt_file(file_path, key)
        click.echo(f"File decrypted successfully to {os.path.splitext(file_path)[0]}")
    except Exception as e:
        click.echo(f"Decryption failed: {e}")

# --- Folder Encryption/Decryption Commands ---

@encryptor.command("encrypt-folder")
@click.argument('folder_path', type=click.Path(exists=True, file_okay=False, readable=True))
@click.option('--password', help='Password to encrypt all files in the folder.', required=True)
def encrypt_folder_cli(folder_path, password):
    click.echo(f"Encrypting all files in {folder_path}...")
    encrypt_folder_with_password(folder_path, password)
    click.echo("Folder encryption complete. Original files have been removed.")

@encryptor.command("decrypt-folder")
@click.argument('folder_path', type=click.Path(exists=True, file_okay=False, readable=True))
@click.option('--password', help='Password to decrypt all files in the folder.', required=True)
def decrypt_folder_cli(folder_path, password):
    click.echo(f"Decrypting all files in {folder_path}...")
    try:
        decrypt_folder_with_password(folder_path, password)
        click.echo("Folder decryption complete. Encrypted files have been removed.")
    except Exception as e:
        click.echo(f"Decryption failed for one or more files. Check the password. Error: {e}")

# --- Key Generation Commands ---

@encryptor.command("generate-key")
@click.option('--from-password', 'from_password', help='Generate a key file from a password.')
def generate_key_cli(from_password):
    if from_password:
        salt = os.urandom(16)
        key = derive_key_from_password(from_password, salt)
        # Note: Storing a key derived this way isn't standard. 
        # The salt would need to be stored with the key.
        # This is a simplified example.
        with open("secret.key", "wb") as key_file:
            key_file.write(b"salted_key_format::" + salt + b"::" + key)
        click.echo("Key generated from password and saved to secret.key")
    else:
        key = generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
        click.echo("New key generated and saved to secret.key")

# --- Other Commands ---

@encryptor.command("caesar")
@click.argument('text')
@click.argument('shift', type=int)
def caesar_cli(text, shift):
    """Encrypts text using the Caesar cipher (for demo purposes)."""
    click.echo(caesar_cipher(text, shift, encrypt=True))


def init_app(app):
    app.cli.add_command(encryptor)
