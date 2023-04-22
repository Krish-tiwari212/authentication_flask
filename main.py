from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = "D:\coding\python\Starting-Files-flask-auth-start\static\files"
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.session_protection = "strong"
db = SQLAlchemy(app)

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
#Line below only required once, when creating DB. 
# db.create_all()

@login_manager.unauthorized_handler
def unauthorized():
    return redirect(url_for('login'))
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        passw = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256:260000', salt_length=8)
        hash_pass = passw[21:]
        new_user = User(email=email, password=hash_pass, name=name)
        db.session.add(new_user)
        db.session.commit()
        return render_template("secrets.html", n=(name.split())[0])
    return render_template("register.html")


@app.route('/login', methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        passw = request.form.get("password")
        meth = 'pbkdf2:sha256:260000$'
        c = User.query.filter_by(email=email).first()
        if c.email == email and check_password_hash(f"{meth}{c.password}",passw):
            login_user(c)
            return render_template("secrets.html", n=((c.name).split())[0])
        else:
            return render_template("login.html", l=1)
    return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html")


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect("/")

@app.route('/download/')
def download():
    return send_from_directory('static', path="files/cheat_sheet.pdf")


if __name__ == "__main__":
    app.run(debug=True)
