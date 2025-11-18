from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
import bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///automarket.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'secret-key-123'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    surname = db.Column(db.String(50), nullable=False)
    login = db.Column(db.String(50), nullable=False, unique=True)
    password_hash = db.Column(db.String(60), nullable=False)
    telephone = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(100))
    address = db.Column(db.Text)

    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

with app.app_context():
    db.create_all()

@app.route('/')
def index():
    user_logged_in = 'user_id' in session
    user_name = session.get('user_name', '')
    return render_template('index.html', user_logged_in=user_logged_in, user_name=user_name)

@app.route('/index')
def index_redirect():
    return redirect(url_for('index'))

@app.route('/catalog')
def catalog():
    user_logged_in = 'user_id' in session
    user_name = session.get('user_name', '')
    return render_template('catalog.html', user_logged_in=user_logged_in, user_name=user_name)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        surname = request.form['surname']
        login = request.form['login']
        password = request.form['password']
        telephone = request.form['telephone']
        email = request.form.get('email', '')
        
        existing_user = User.query.filter_by(login=login).first()
        if existing_user:
            flash('Пользователь с таким логином уже существует', 'error')
            return render_template('register.html')
        
        new_user = User(
            name=name,
            surname=surname,
            login=login,
            telephone=telephone,
            email=email
        )
        new_user.set_password(password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Регистрация успешна! Теперь вы можете войти.', 'success')
            return redirect(url_for('login'))
        except:
            db.session.rollback()
            flash('Ошибка при регистрации', 'error')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']
        
        user = User.query.filter_by(login=login).first()
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['user_login'] = user.login
            session['user_name'] = user.name
            flash(f'Добро пожаловать, {user.name}!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Неверный логин или пароль', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('index'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        flash('Пожалуйста, войдите в систему', 'error')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        user.name = request.form.get('firstName', user.name)
        user.surname = request.form.get('lastName', user.surname)
        user.telephone = request.form.get('phone', user.telephone)
        user.email = request.form.get('email', user.email)
        user.address = request.form.get('address', user.address)
        
        try:
            db.session.commit()
            session['user_name'] = user.name
            flash('Данные успешно обновлены!', 'success')
            return redirect(url_for('profile'))
        except:
            db.session.rollback()
            flash('Ошибка при обновлении данных', 'error')
    
    return render_template('profile.html', 
                         user_logged_in=True, 
                         user_name=session['user_name'],
                         user_data=user)

@app.route('/cart')
def cart():
    if 'user_id' not in session:
        flash('Пожалуйста, войдите в систему', 'error')
        return redirect(url_for('login'))
    return render_template('shopping_cart.html', user_logged_in=True, user_name=session['user_name'])

@app.route('/empty_cart')
def empty_cart():
    if 'user_id' not in session:
        flash('Пожалуйста, войдите в систему', 'error')
        return redirect(url_for('login'))
    return render_template('empty_shopping_cart.html', user_logged_in=True, user_name=session['user_name'])

@app.route('/order')
def order():
    if 'user_id' not in session:
        flash('Пожалуйста, войдите в систему', 'error')
        return redirect(url_for('login'))
    return render_template('order.html', user_logged_in=True, user_name=session['user_name'])

@app.route('/making_purchase')
def making_purchase():
    if 'user_id' not in session:
        flash('Пожалуйста, войдите в систему', 'error')
        return redirect(url_for('login'))
    return render_template('making_a_purchase.html', user_logged_in=True, user_name=session['user_name'])

@app.route('/successful_purchase')
def successful_purchase():
    if 'user_id' not in session:
        flash('Пожалуйста, войдите в систему', 'error')
        return redirect(url_for('login'))
    return render_template('successful_purchase.html', user_logged_in=True, user_name=session['user_name'])

@app.route('/partners')
def partners():
    user_logged_in = 'user_id' in session
    user_name = session.get('user_name', '')
    return render_template('partners.html', user_logged_in=user_logged_in, user_name=user_name)

@app.route('/suppliers')
def suppliers():
    user_logged_in = 'user_id' in session
    user_name = session.get('user_name', '')
    return render_template('suppliers.html', user_logged_in=user_logged_in, user_name=user_name)

if __name__ == '__main__':
    app.run(debug=True)