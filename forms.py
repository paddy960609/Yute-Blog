from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditorField, CKEditor
from flask import Flask

app = Flask(__name__)
ckeditor = CKEditor(app)

##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")

class RegisterForm(FlaskForm):
    email = StringField("User Email", validators=[DataRequired()])
    password = PasswordField("User Password", validators=[DataRequired()])
    name = StringField("User Name", validators=[DataRequired()])
    submit = SubmitField("Sign me UP!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

class LoginForm(FlaskForm):
    email = StringField("User Email", validators=[DataRequired()])
    password = PasswordField("User Password", validators=[DataRequired()])
    submit = SubmitField("Sign me IN!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

class CommentForm(FlaskForm):

    comment_text = CKEditorField('Comment', validators=[DataRequired()])
    submit = SubmitField('Submit Comment')
