from flask import Flask, render_template, request, flash, redirect, send_from_directory
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from flask_wtf.form import _Auto
from wtforms import StringField, PasswordField, BooleanField, SubmitField, IntegerField, FloatField, SelectField, ValidationError
from wtforms.validators import DataRequired, Length, NumberRange
from wtforms import validators
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, backref
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
import os
import sys

app = Flask(__name__)
app.config['SECRET_KEY'] = 'joe mama'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'+sys.path[0]+r'\instance\data.sqlite3'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = '/log-in'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


class User(db.Model, UserMixin):

    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(16), unique=True)
    password = db.Column(db.String(100))

    items = db.relationship('Item', secondary='orders')

    
class Item(db.Model):

    __tablename__ = 'items'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(16), unique=True)
    name_nospaces = db.Column(db.String(16), unique=True)
    picture = db.Column(db.String(16), unique=True)
    description = db.Column(db.String(280))
    price = db.Column(db.Float)
    env_impact = db.Column(db.Integer)

    users = db.relationship('User', secondary='orders')

class Order(db.Model):

    __tablename__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    item_id = db.Column(db.Integer, db.ForeignKey('items.id'))
    quantity = db.Column(db.Integer)

    user = relationship(User, backref=backref("orders", cascade="all, delete-orphan"))
    product = relationship(Item, backref=backref("orders", cascade="all, delete-orphan"))


class LoginForm(FlaskForm):

    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember me')
    submit = SubmitField('Log in')

class SignupForm(FlaskForm):

    username = StringField('Username', validators=[DataRequired(), Length(5, 16)])
    password = PasswordField('Password', validators=[DataRequired(), Length(8, 16)])
    confirm_password = PasswordField('Confirm password', validators=[DataRequired(), Length(8, 16)])
    submit = SubmitField('Sign up')


class AddToBasketForm(FlaskForm):
   
    quantity = IntegerField('Quantity: ', validators=[NumberRange(1, 99)], default=1)
    submit = SubmitField('Add to basket')


class RemoveFromBasketForm(FlaskForm):
    
    submit = SubmitField('Remove from basket')





class CheckoutForm(FlaskForm):

    card_number = StringField('Card number: ', validators=[Length(16, 16)])

    expiry = StringField('Expiry date: ', validators=[Length(5, 5)])
     
    cvv = StringField('CVV: ', validators=[Length(3, 3)])

    submit = SubmitField('Checkout')



    




@app.route('/', methods=['GET', 'POST'])
def index():

    items = Item.query.all()

    if current_user.is_authenticated:
        for item in items:

            if item in current_user.items:
                item.form = RemoveFromBasketForm()
                item.in_basket = True

            else:
                item.form = AddToBasketForm()
                item.in_basket = False
    

        


    if request.method == 'POST':

        print(request.form)

        if 'quantity' in request.form:

            item_id = list(request.form)[1]
            item_id = int(item_id[6:])
            quantity = request.form['quantity']
            print(current_user.id, item_id, quantity)
            order = Order(user_id=current_user.id, item_id=item_id, quantity=quantity)
            db.session.add(order)
            db.session.commit()

            
            
        if request.form[list(request.form)[0]] == 'Remove from basket':

            item_id = list(request.form)[0]

            item_id = int(item_id[6:])
            print(current_user.id, item_id)
            order = Order.query.filter_by(user_id=current_user.id, item_id=item_id).first()
            db.session.delete(order)
            db.session.commit()
   
        

        return redirect('/')        

    return render_template('home.html', items=items, current_user=current_user)

@app.route('/log-in', methods=['GET', 'POST'])
def log_in():

    form = LoginForm()
    
    if request.method == 'POST':

        username = form.username.data
        password = form.password.data
        remember = form.remember.data

        user = User.query.filter_by(username=username).first()

        if user:
            if check_password_hash(user.password, password):

                login_user(user, remember=remember)
                return redirect('/')

            else:
                flash('Incorrect password', category=False)
                
        else:
            flash('User does not exist.', category='error')


    return render_template("log-in.html", current_user=current_user, form=form)

@login_required
@app.route('/log-out')
def log_out():
    logout_user()
    return redirect('/')


@app.route('/sign-up', methods=['GET', 'POST'])
def sign_up():

    form = SignupForm()
    match = None
    
    if request.method == 'POST':

        username = form.username.data
        password = form.password.data
        confirm_password = form.confirm_password.data

        user = User.query.filter_by(username=username).first()

        if user:
            flash('That username is taken', category='error')
        
        elif password != confirm_password:
            flash("Passwords do not match.", category='error')

        else:
            new_user = User(username=username, password=generate_password_hash(password, method='scrypt'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect('/')




    return render_template("sign-up.html", current_user=current_user, form=form, match=match)

@app.route('/item/<name_nospaces>', methods=['GET', 'POST'])
def item(name_nospaces):

    item = Item.query.filter_by(name_nospaces=name_nospaces).first()

    add_form = AddToBasketForm()
    remove_form = RemoveFromBasketForm()

    if current_user.is_authenticated:


        if request.method == 'POST':

            if 'quantity' in request.form:

                quantity = add_form.quantity.data
                order = Order(user_id=current_user.id, item_id=item.id, quantity=quantity)
                db.session.add(order)
                db.session.commit()

            else:

                order = Order.query.filter_by(user_id=current_user.id, item_id=item.id).first()
                db.session.delete(order)
                db.session.commit()
            

        if item in current_user.items:
            in_basket = True
        else:
            in_basket = False

    else:
        in_basket = False

    

    return render_template('item.html', item=item, current_user=current_user, in_basket=in_basket, add_form=add_form, remove_form=remove_form)


@login_required
@app.route('/basket', methods=['GET', 'POST'])
def basket():
    
    items = current_user.items
    if len(items) == 0:
        return render_template('basket.html', items=items, total=0, empty=True)

    else:

        total = 0
        for item in items:
            order = Order.query.filter_by(user_id=current_user.id, item_id=item.id).first()
            item.form = AddToBasketForm()
            item.quantity = order.quantity
            items_price = item.price*item.quantity
            total += items_price


        if request.method == 'POST':

            item_id = list(request.form)[0]

            item_id = int(item_id[6:])
            order = Order.query.filter_by(user_id=current_user.id, item_id=item_id).first()
            db.session.delete(order)
            db.session.commit()

            return redirect('/basket')
            
        
        total = "{:.2f}".format(total)
        return render_template('basket.html', items=items, total=total, empty=False)

    
@login_required
@app.route('/checkout', methods=['GET', 'POST'])
def checkout():

    form = CheckoutForm()

    if request.method == 'POST':
        orders = Order.query.filter_by(user_id=current_user.id).all()
        for order in orders:
            db.session.delete(order)
        db.session.commit()
        return render_template('checkout.html', dispatched=True)
    
    return render_template('checkout.html', form=form, dispatched=False)

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        app.run(debug=True)

