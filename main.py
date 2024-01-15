from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta, timezone
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from forms import RegistrationForm
from collections import defaultdict
import pytz
from sqlalchemy import func
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from flask_migrate import Migrate
import re


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///training_data.db'
app.config ['SECRET_KEY'] = 'NICE_BALLZ_LOLZ'
db = SQLAlchemy(app)
migrate = Migrate(app,db)



#DATABASE MODELS kekw
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key= True)
    username = db.Column(db.String(50), unique=True, nullable = False)
    password = db.Column (db.String(75), nullable=False)
    training_record = db.relationship ('TrainingRecord', backref = 'user')
    drills = db.relationship('Drill', backref='user', lazy=True)
    def set_password (self, password):
        self.password = generate_password_hash(password)
    def check_password (self,password):
        return check_password_hash(self.password, password)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    drills = db.relationship('Drill', backref='category', lazy=True)

class Drill(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    training_records = db.relationship('TrainingRecord', backref='drill', lazy=True)
    user_id = db.Column (db.Integer, db.ForeignKey('user.id'), nullable= False)
class TrainingRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    time_spent = db.Column(db.Integer, nullable=False)
    date = db.Column(db.Date, default=datetime.now(timezone.utc).date)
    drill_id = db.Column(db.Integer, db.ForeignKey('drill.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

with app.app_context():
    db.create_all()

    technical_category = Category.query.filter_by(name='Technical').first()
    physical_category = Category.query.filter_by(name='Physical').first()
    longball_shooting_category = Category.query.filter_by(name='Longball/Shooting').first()
    tactical_category = Category.query.filter_by(name='Tactical').first()

    # category names lol
    if technical_category:
        technical_category.name = 'Technical'
    else:
        technical_category = Category(name='Technical')
        db.session.add(technical_category)

    if physical_category:
        physical_category.name = 'Physical'
    else:
        physical_category = Category(name='Physical')
        db.session.add(physical_category)

    if longball_shooting_category:
        longball_shooting_category.name = 'Longball/Shooting'
    else:
        longball_shooting_category = Category(name='Longball/Shooting')
        db.session.add(longball_shooting_category)

    if tactical_category:
        tactical_category.name = 'Tactical'
    else:
        tactical_category = Category(name='Tactical')
        db.session.add(tactical_category)

    db.session.commit()

    categories = [technical_category, physical_category, longball_shooting_category, tactical_category]
    for category in categories:
        db.session.add(category)

    db.session.commit()


#authentication kys (keep yourself safe :)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


#routes :DD
@app.route('/')
@login_required
def index():
    categories = Category.query.all()
    drills = Drill.query.filter_by(user = current_user).all()
    return render_template('index.html', categories=categories, drills=drills)

@app.route('/add_training_record', methods=['POST'])
@login_required
def add_training_record():
    time_spent = int(request.form['time_spent'])
    drill_id = int(request.form['drill'])
    training_date_str = request.form['training_date']
    
    try:
        training_date = datetime.strptime(training_date_str, '%Y-%m-%d').date()
    except ValueError:
        flash('Invalid date format. Please use YYYY-MM-DD.')
        return redirect(url_for('index'))

    drill = Drill.query.get(drill_id)
    training_record = TrainingRecord(time_spent=time_spent, date = training_date, drill=drill, user=current_user)
    db.session.add(training_record)
    db.session.commit()
    
    flash('Training record added!')
    return redirect(url_for('index'))

@app.route('/add_drill', methods = ['POST'])
@login_required
def add_drill():
    drill_name = request.form['drill_name']
    category_id = int(request.form['category_id'])
    category = Category.query.get(category_id)
    drill = Drill(name=drill_name, category=category, user=current_user)
    db.session.add(drill)
    db.session.commit()

    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

Username_Pattern = re.compile("^[a-zA-Z0-9]{5,15}$")

@app.route ('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        if not Username_Pattern.search (username):
            flash('Invalid username format. Usernames must be 3-20 characters long and can only contain letters, numbers, underscores, and hyphens.')
            return redirect(url_for('register'))
        else:
            new_user = User(username=form.username.data)
            new_user.set_password(form.password.data)
            db.session.add(new_user)
            db.session.commit()

        flash ('Your account has been created!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route('/statistics')
@login_required
def statistics():

    if request.method == 'POST':
        record_id = request.form.get('record_id')
        if record_id:
            record = TrainingRecord.query.get(record_id)
            if record:
                db.session.delete(record)
                db.session.commit()

    categories = Category.query.all()

    daily_totals = defaultdict(int)
    weekly_totals = defaultdict(int)
    monthly_totals = defaultdict(int)
    category_totals = defaultdict(int)
    category_times = defaultdict(lambda: defaultdict(int))
    all_dates = set()

    for category in categories:
        drills_in_category = Drill.query.filter_by(category=category, user=current_user).all()

        for drill in drills_in_category:
            training_records = TrainingRecord.query.filter_by(drill=drill, user=current_user).all()

            for record in training_records:
                record_date = record.date.strftime('%Y-%m-%d')
                all_dates.add(record_date)
                daily_totals[record_date] += record.time_spent

                record_week = record.date.isocalendar()[1]
                weekly_totals[record_week] += record.time_spent
                record_month = record.date.month
                monthly_totals[record_month] += record.time_spent

                category_totals[drill.category] += record.time_spent   
                category_times[record_date][category.name] += record.time_spent

    all_dates = sorted(all_dates) 
    num_days = len(all_dates)
    total_time = sum(daily_totals.values())
    num_weeks = len(weekly_totals)
    num_months = len(monthly_totals)

    if num_days != 0:
        average_time_per_day = total_time / num_days
    else: 
        average_time_per_day = 0 
    if num_weeks != 0:
        average_time_per_week = total_time / num_weeks
    else: 
        average_time_per_week = 0 
    if num_months != 0:
        average_time_per_month = total_time / num_months
    else: 
        average_time_per_month = 0 

    average_time_per_category = {
        category.name: (category_totals[category] / total_time) * 100 if total_time != 0 else 0
        for category in categories
    }

    return render_template(
        'statistics.html',
        categories=categories,
        daily_totals=daily_totals,
        category_times= category_times,
        total_time=total_time,
        num_days=num_days,
        average_time_per_day=round(average_time_per_day, 1),
        average_time_per_week=round(average_time_per_week, 1),
        average_time_per_month=round(average_time_per_month, 1),
        average_time_per_category=average_time_per_category
    )

#final route epic
@app.route('/reset_logs', methods = ['POST'])
@login_required
def reset_logs():
    TrainingRecord.query.delete()
    db.session.commit()
    return redirect(url_for('statistics'))



if __name__ == '__main__':
    app.run(debug = False, host = '0.0.0.0', port = 5000)