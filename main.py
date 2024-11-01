from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'

# CREATE DATABASE
class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# 로그인 메니저 생성
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    # User.get 속성이 없어서 query 사용
    return User.query.get(user_id)

# CREATE TABLE IN DB
class User(db.Model, UserMixin):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))
    
    def get_id(self):
        return str(self.id)

with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)

@app.route('/register', methods=["GET","POST"])
def register():
    if request.method == "POST":
        existing_user = User.query.filter_by(email=request.form['email']).first()
        hashed_password = generate_password_hash(
            request.form['password'],
            method='pbkdf2:sha256',
            salt_length=8,
            )
        
        if not existing_user:
            user = User(
                name = request.form['name'],
                email = request.form['email'],
                password = hashed_password,      
            )
            db.session.add(user)
            db.session.commit()
            flash("Register successed!")
            return redirect(url_for('home', user_id=user.id, logged_in=current_user.is_authenticated ))
    
    return render_template("register.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash("logged in!")
            return redirect(url_for('secrets'))
        
        else :
            flash("Invalid email of password", 'danger')
            return redirect(url_for('login'))
    return render_template("login.html")

# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     form = request.form
#     users = User.query.all()
#     for user in users:
#         if user.email == form.email and user.passowrd == form.password:
#             login_user(user)
#         Flask.flash('Logged in successfully!')
#         next = Flask.request.args.get('next')
        
#         # if not url_has_allowed_host_and_scheme(next, request.host):
#         #     return Flask.abort(400)
        
#         return redirect('secrets', user_id=user.id)
#     # user = request.get_by_email(request.form['email'])
#     # if form.validato_on_submit():
#     #     login_user(user)
#     #     Flask.flash('Logged in successfully!')
#     #     next = Flask.request.args.get('next')
        
#     #     # if not url_has_allowed_host_and_scheme(next, request.host):
#     #     #     return Flask.abort(400)
        
#     #     return redirect('secrets', user_id=user.id)
        
#     return render_template("login.html")

@app.route('/secrets')
def secrets():
    print(current_user.name)
    return render_template("secrets.html", user=current_user, logged_in=True)

@app.route('/logout')
def logout():
    logout_user()
    return render_template('index.html')

@app.route('/download/<cheat_sheet>')
def download(cheat_sheet):
    return send_from_directory(
        './static/files', f'{cheat_sheet}.pdf'
    )

if __name__ == "__main__":
    app.run(debug=True)
