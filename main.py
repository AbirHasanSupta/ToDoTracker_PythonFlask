from flask import Flask, render_template, redirect, url_for, flash, abort, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_bootstrap import Bootstrap5
from flask_wtf import FlaskForm
from wtforms import SubmitField, EmailField, StringField, PasswordField, DateField
from wtforms.validators import DataRequired
from flask_login import login_required, UserMixin, login_user, LoginManager, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_ckeditor import CKEditorField,CKEditor

app = Flask(__name__)
app.config['SECRET_KEY'] = 'blabla'
Bootstrap5(app)
app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///users.db'

login_manager = LoginManager()
login_manager.init_app(app)

ckeditor = CKEditor(app)


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


db = SQLAlchemy()
db.init_app(app)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    todos = relationship("List", back_populates="author")


class List(db.Model):
    __tablename__ = 'lists'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), nullable=False)
    description = db.Column(db.String, nullable=False)
    date = db.Column(db.String(250), nullable=False)
    complete = db.Column(db.Boolean)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship("User", back_populates="todos")


class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In', validators=[DataRequired()])


class RegisterForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up', validators=[DataRequired()])


class ToDo(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    description = CKEditorField("Description", validators=[DataRequired()])
    date = DateField("Due Date", format='%Y-%m-%d', validators=[DataRequired()])
    submit = SubmitField("Add", validators=[DataRequired()])


with app.app_context():
    db.create_all()


date_today = datetime.now()
date_formatted = date_today.strftime('%Y-%m-%d')


@app.route('/', methods=['GET', 'POST'])
def home():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        user = db.session.execute(db.select(User).where(User.email == register_form.email.data)).scalar()

        if user:
            flash("You Have Already Signed Up With That Email. Log In Instead!")
            return redirect(url_for('home'))
        hashed_password = generate_password_hash(register_form.password.data, method='pbkdf2:sha256', salt_length=8)
        new_user = User(
            name=register_form.name.data,
            email=register_form.email.data,
            password=hashed_password

        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('todo'))

    return render_template('index.html', form=register_form, current_user=current_user, date=date_formatted)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        password = form.password.data
        user = db.session.execute(db.select(User).where(User.email == form.email.data)).scalar()
        if user:
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('home'))
            else:
                flash("Password Incorrect, Try again!")
                return redirect(url_for('login'))
        else:
            flash("This email does not exist. Try again with proper email.")
            return redirect(url_for('login'))

    return render_template('login.html', form=form, current_user=current_user)


@app.route('/todo', methods=["POST", "GET"])
@login_required
def todo():
    form = ToDo()
    if form.validate_on_submit():
        new_todo = List(
            title=form.title.data,
            description=form.description.data,
            date=form.date.data,
            complete=False,
            author=current_user
        )
        db.session.add(new_todo)
        db.session.commit()
        return redirect(url_for('todo'))
    user_todo = current_user.todos
    return render_template('todo.html', current_user=current_user, form=form,
                           user_todo=user_todo, date=date_formatted)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/delete/<int:id>')
@login_required
def delete(id):
    redirect_to = request.args.get("redirect_to", 'home')
    delete_todo = db.get_or_404(List, id)
    if current_user.id == delete_todo.author_id:
        db.session.delete(delete_todo)
        db.session.commit()
        if redirect_to == "todo":
            return redirect(url_for('todo'))
        else:
            return redirect(url_for("home"))


@app.route("/description/<int:id>", methods=["GET", "POST"])
@login_required
def expand(id):
    redirect_to = request.args.get("redirect_to", "home")
    expand_todo = db.get_or_404(List, id)
    date = datetime.strptime(expand_todo.date, '%Y-%m-%d')
    form = ToDo(
        title=expand_todo.title,
        description=expand_todo.description,
        date=date
    )

    if current_user.id == expand_todo.author_id:
        if form.validate_on_submit():
            expand_todo.title = form.title.data
            expand_todo.description = form.description.data
            expand_todo.date = form.date.data
            db.session.commit()
            if redirect_to == "todo":
                return redirect(url_for('todo'))
            else:
                return redirect(url_for("home"))

    else:
        return abort(403, "You are not allowed to access this resource.")

    return render_template("description.html", form=form)


@app.route('/complete/<int:id>', methods=["GET"])
@login_required
def complete(id):
    redirect_to = request.args.get("redirect_to", 'home')
    complete_todo = db.get_or_404(List, id)
    if current_user.id == complete_todo.author_id:
        complete_todo.complete = not complete_todo.complete
        db.session.commit()
        if redirect_to == "todo":
            return redirect(url_for('todo'))
        else:
            return redirect(url_for("home"))
    else:
        return abort(403, "You are not allowed to access this resource.")


if __name__ == '__main__':

    app.run(debug=True, port=5000)