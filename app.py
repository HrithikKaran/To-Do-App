from flask import Flask, render_template, url_for, redirect, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todos.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)
login_manager= LoginManager(app)
login_manager.login_view = 'login'


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)  # primary keys are required by SQLAlchemy
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    todos = db.relationship('Todo', backref='user', lazy=True)



class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    desc = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, default = datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)



@app.route('/')
def home():
    return render_template('index.html')

@app.route('/profile', methods= ['POST', 'GET'])
@login_required
def profile():
    if request.method=='POST':
        title = request.form['title']
        desc = request.form['description']
        todo = Todo(title=title, desc=desc, user=current_user)
        db.session.add(todo)
        db.session.commit()
    all_todos = Todo.query.filter_by(user=current_user).all()
    return render_template('profile.html', todos= all_todos)




@app.route('/update/<int:id>', methods=['POST', 'GET'])
def update(id):
    todo = Todo.query.get_or_404(id)
    if request.method == 'POST':
        title = request.form['title']
        desc = request.form['description']
        todo = Todo.query.filter_by(id = id).first()
        todo.title = title
        todo.desc = desc
        #db.session.add(todo)
        db.session.commit()
        return redirect(url_for('profile'))
    #todo = Todo.query.filter_by(id = id).first()
    return render_template('update.html', todo=todo)

@app.route('/delete/<int:id>')
def delete(id):
    todo = Todo.query.get_or_404(id)
    #todo = Todo.query.filter_by(id =id).first()
    db.session.delete(todo)
    db.session.commit()
    return redirect(url_for('profile'))

@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/signup')
def signup():
    return render_template('signup.html')


@app.route('/signup', methods=[ 'POST'])
def signup_post():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')


    user = User.query.filter_by(email=email).first()

    if user:
        flash("Email Already Exits!")
        return redirect(url_for('login'))

    hashed_password = generate_password_hash(password, method = 'pbkdf2:sha256')
    new_user = User(email=email, name=name, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()


    return redirect(url_for('login'))



@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')

    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()

    # check if user actually exists
    # take the user supplied password, hash it, and compare it to the hashed password in database
    if not user or not check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        return redirect(url_for('login'))  # if user doesn't exist or password is wrong, reload the page

    # if the above check passes, then we know the user has the right credentials
    login_user(user, remember=remember)
    return redirect(url_for('profile'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))




if __name__== "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)