from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from http import HTTPStatus


app = Flask(__name__)

app.config['SECRET_KEY'] = 'denemeler123-=,.alpernesibe'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
#Line below only required once, when creating DB. 
# db.create_all()


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == "POST":
        name = request.form.get('name')
        password = request.form.get('password')
        email = request.form.get('email')
        if not User.query.filter_by(email=email).first():
            deneme = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
            new_user = User(email=email, password=deneme, name=name)
            db.session.add(new_user)
            db.session.commit()
            return render_template("secrets.html", name=name)
        else:
            error = 'This mail address is already registered!'
            return render_template("register.html", error=error)
    return render_template("register.html")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@login_manager.unauthorized_handler
def unauthorized():
    if request.blueprint == 'api':
        HTTPStatus.UNAUTHORIZED
    return redirect(url_for('site.login'))

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')
        user_data =User.query.filter_by(email=email).first()
        if user_data:
            if check_password_hash(user_data.password, password):
                login_user(user_data)
                # name = user_data.name
                return redirect(url_for('secrets'))
            else:
                error = 'Your mail or password is wrong'
                return render_template("login.html", error=error)
        else:
            error = 'Your mail or password is wrong'
            return render_template("login.html", error=error)
    return render_template("login.html")


@app.route('/secrets')
def secrets():
    print(current_user.name)
    return render_template("secrets.html", name=current_user.name, logged_in=True)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/download/<path:name>", methods=["GET", "POST"])
@login_required
def download_file(name):
    return send_from_directory(directory='static/files/',  filename=name, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)
