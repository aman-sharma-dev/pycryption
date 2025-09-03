from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, PasswordField, FileField, SubmitField
from wtforms.validators import DataRequired, Optional

class TextEncryptionForm(FlaskForm):
    """Form for encrypting or decrypting a block of text."""
    text_input = TextAreaField('Text', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class FileEncryptionForm(FlaskForm):
    """Form for uploading a file to be encrypted or decrypted."""
    file_upload = FileField('File', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
