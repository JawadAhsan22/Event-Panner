from dotenv import load_dotenv
load_dotenv()
import os
from flask import Flask, request, redirect, url_for, render_template, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
import sqlite3
from sqlite3 import IntegrityError

app = Flask(__name__)
app.secret_key = 'your_very_secret_key'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
app.secret_key = os.getenv("SECRET_KEY")
app.config['MAIL_DEFAULT_SENDER'] = 'a.jawad2731@gmail.com'

mail = Mail(app)

def create_db():
    conn = sqlite3.connect('event_planner.db')
    c = conn.cursor()
    
    c.execute('DROP TABLE IF EXISTS User;')
    c.execute('DROP TABLE IF EXISTS Event;')
    c.execute('DROP TABLE IF EXISTS Invitation;')
    
    
    c.execute('''
        CREATE TABLE User (
            UserID INTEGER PRIMARY KEY AUTOINCREMENT,
            Name TEXT,
            Email TEXT UNIQUE,
            Password TEXT,
            Role TEXT DEFAULT 'user'
        );
    ''')
    c.execute('''
        CREATE TABLE Event (
            EventID INTEGER PRIMARY KEY AUTOINCREMENT,
            OrganizerID INTEGER,
            Title TEXT,
            Description TEXT,
            Location TEXT,
            DateTime TEXT,
            FOREIGN KEY(OrganizerID) REFERENCES User(UserID)
        );
    ''')
    c.execute('''
        CREATE TABLE Invitation (
            InvitationID INTEGER PRIMARY KEY AUTOINCREMENT,
            EventID INTEGER,
            GuestID INTEGER,
            SentDate TEXT DEFAULT (DATE('now')),  
            RSVPStatus TEXT DEFAULT 'Pending',
            FOREIGN KEY(EventID) REFERENCES Event(EventID),
            FOREIGN KEY(GuestID) REFERENCES User(UserID)
        );
    ''')
    conn.commit()
    conn.close()


@app.route('/session')
def show_session():
    return str(session)


@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = sqlite3.connect('event_planner.db')
        c = conn.cursor()
        c.execute('SELECT UserID, Name, Email, Password FROM User WHERE Email = ?', (email,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[3], password):
            session['user_id'] = user[0]
            session['user_name'] = user[1]
            session['user_email'] = user[2]  
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'error')

    return render_template('login.html')


@app.route('/dashboard', methods=['GET'])
def dashboard():
    if 'user_id' not in session:
        flash('Please login to access the dashboard.', 'warning')
        return redirect(url_for('login'))
    
    return render_template('dashboard.html')


@app.route('/create_event', methods=['GET', 'POST'])
def create_event():
    if 'user_id' not in session:
        flash('Please login to create an event.', 'warning')
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        location = request.form['location']
        date = request.form['date']
        time = request.form['time']
        datetime = f"{date} {time}"
        conn = sqlite3.connect('event_planner.db')
        c = conn.cursor()
        c.execute('INSERT INTO Event (OrganizerID, Title, Description, Location, DateTime) VALUES (?, ?, ?, ?, ?)',
                  (session['user_id'], title, description, location, datetime))
        event_id = c.lastrowid
        conn.commit()
        flash(f'Event created successfully! Event ID: {event_id}', 'success')
        return redirect(url_for('dashboard'))
    return render_template('create_event.html')

@app.route('/send_invitation', methods=['GET', 'POST'])
def send_invitation():
    if 'user_id' not in session:
        flash('Please login to send invitations.', 'warning')
        return redirect(url_for('login'))
    if request.method == 'POST':
        event_id = request.form['event_id']
        guest_email = request.form['guest_email']
        
        conn = sqlite3.connect('event_planner.db')
        c = conn.cursor()
        
        c.execute('SELECT UserID FROM User WHERE Email = ?', (guest_email,))
        guest = c.fetchone()

        if guest:
            
            c.execute('INSERT INTO Invitation (EventID, GuestID, SentDate, RSVPStatus) VALUES (?, ?, DATE(\'now\'), \'Pending\')', (event_id, guest[0]))
            conn.commit()
            
            
            msg = Message("You're Invited!", recipients=[guest_email])
            msg.body = f'You have been invited to an event! Please check our platform for more details. Respond by visiting: {url_for("event_invitations", _external=True)}'
            mail.send(msg)
            flash('Invitation sent successfully!', 'success')
        else:
            flash('No user found with that email.', 'error')

        conn.close()
        return redirect(url_for('dashboard'))
    return render_template('send_invitation.html')


@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = sqlite3.connect('event_planner.db')
    c = conn.cursor()
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email'].lower()
        c.execute('UPDATE User SET Name = ?, Email = ? WHERE UserID = ?', (name, email, user_id))
        conn.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    else:
        c.execute('SELECT * FROM User WHERE UserID = ?', (user_id,))
        user = c.fetchone()
        conn.close()
        return render_template('edit_profile.html', user=user)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email'].lower()  
        password = request.form['password']
        hashed_password = generate_password_hash(password)

        conn = sqlite3.connect('event_planner.db')
        c = conn.cursor()

        
        if email == 'a.jawad2731@gmail.com':
            role = 'admin'
        else:
            role = 'user'

        try:
            c.execute('INSERT INTO User (Name, Email, Password, Role) VALUES (?, ?, ?, ?)', (name, email, hashed_password, role))
            conn.commit()
            flash('Registered successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            flash('This email is already registered.', 'error')
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/users', methods=['GET', 'POST'])
def users():
    if 'user_id' not in session:
        flash('You need to log in to view this page.', 'warning')
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('event_planner.db')
    c = conn.cursor()
    
    c.execute('SELECT Role FROM User WHERE UserID = ?', (session['user_id'],))
    role = c.fetchone()[0]

    if role != 'admin':
        flash('You must be an admin to view this page.', 'error')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        user_action = request.form.get('promote', request.form.get('demote', request.form.get('delete')))
        if 'promote' in request.form:
            c.execute('UPDATE User SET Role = "admin" WHERE UserID = ?', (user_action,))
            flash('User promoted to admin successfully.', 'success')
        elif 'demote' in request.form:
            c.execute('UPDATE User SET Role = "user" WHERE UserID = ?', (user_action,))
            flash('User demoted successfully.', 'info')
        elif 'delete' in request.form:
            c.execute('DELETE FROM User WHERE UserID = ?', (user_action,))
            flash('User deleted successfully.', 'warning')
        conn.commit()

    c.execute('SELECT UserID, Name, Email, Role FROM User')
    users = c.fetchall()
    conn.close()
    return render_template('users.html', users=users)



@app.route('/my_events', methods=['GET'])
def my_events():
    if 'user_id' not in session:
        flash('Please login to access this page.', 'warning')
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('event_planner.db')
    c = conn.cursor()
    c.execute('SELECT * FROM Event WHERE OrganizerID = ?', (session['user_id'],))
    my_events = c.fetchall()
    conn.close()
    return render_template('my_events.html', my_events=my_events)

@app.route('/event_invitations', methods=['GET'])
def event_invitations():
    if 'user_id' not in session:
        flash('Please login to access this page.', 'warning')
        return redirect(url_for('login'))

    conn = sqlite3.connect('event_planner.db')
    c = conn.cursor()
    c.execute('''SELECT Event.Title, Event.DateTime, Invitation.RSVPStatus, Invitation.InvitationID
                 FROM Event
                 JOIN Invitation ON Event.EventID = Invitation.EventID
                 WHERE Invitation.GuestID = ?''', (session['user_id'],))
    invitations = c.fetchall()
    conn.close()

    return render_template('event_invitations.html', invitations=invitations)


@app.route('/delete_event/<int:event_id>', methods=['POST'])
def delete_event(event_id):
    if 'user_id' not in session:
        flash('Please login to perform this action.', 'warning')
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('event_planner.db')
    c = conn.cursor()
    
    
    c.execute('SELECT User.Email FROM User JOIN Invitation ON User.UserID = Invitation.GuestID WHERE Invitation.EventID = ?', (event_id,))
    guests = c.fetchall()
    for guest_email, in guests:
        msg = Message("Event Cancelled", recipients=[guest_email])
        msg.body = "We regret to inform you that the event you were invited to has been cancelled."
        mail.send(msg)
    
    
    c.execute('DELETE FROM Event WHERE EventID = ? AND OrganizerID = ?', (event_id, session['user_id']))
    conn.commit()
    conn.close()
    flash('Event deleted successfully!', 'success')
    return redirect(url_for('my_events'))

@app.route('/respond_invitation/<int:invitation_id>/<response>', methods=['POST'])
def respond_invitation(invitation_id, response):
    if 'user_id' not in session:
        flash('Please login to perform this action.', 'warning')
        return redirect(url_for('login'))

    conn = sqlite3.connect('event_planner.db')
    c = conn.cursor()

    
    c.execute('UPDATE Invitation SET RSVPStatus = ? WHERE InvitationID = ?', (response, invitation_id))
    conn.commit()

    
    c.execute('''
        SELECT User.Email FROM User
        JOIN Event ON Event.OrganizerID = User.UserID
        JOIN Invitation ON Invitation.EventID = Event.EventID
        WHERE Invitation.InvitationID = ?
    ''', (invitation_id,))
    organizer_email = c.fetchone()[0]

    msg = Message("Invitation Response", recipients=[organizer_email])
    msg.body = f"A guest has {response} the invitation to your event."
    mail.send(msg)

    flash(f'You have {response} the invitation.', 'success')
    conn.close()
    return redirect(url_for('event_invitations'))


@app.route('/edit_event/<int:event_id>', methods=['GET', 'POST'])
def edit_event(event_id):
    if 'user_id' not in session:
        flash('Please login to access this page.', 'warning')
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('event_planner.db')
    c = conn.cursor()
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        location = request.form['location']
        date = request.form['date']
        time = request.form['time']
        datetime = f"{date} {time}"
        
        
        c.execute('UPDATE Event SET Title = ?, Description = ?, Location = ?, DateTime = ? WHERE EventID = ? AND OrganizerID = ?',
                  (title, description, location, datetime, event_id, session['user_id']))
        conn.commit()
        flash('Event updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    else:
        
        c.execute('SELECT Title, Description, Location, DateTime FROM Event WHERE EventID = ? AND OrganizerID = ?', (event_id, session['user_id']))
        event = c.fetchone()
        conn.close()
        if event:
            return render_template('edit_event.html', event=event, event_id=event_id)
        else:
            flash('Event not found or you do not have permission to edit it.', 'error')
            return redirect(url_for('dashboard'))

    return render_template('edit_event.html', event_id=event_id)
def add_missing_column():
    conn = sqlite3.connect('event_planner.db')
    c = conn.cursor()
    try:
        c.execute('ALTER TABLE Invitation ADD COLUMN RSVPStatus TEXT DEFAULT \'Pending\'')
        conn.commit()
    except sqlite3.OperationalError as e:
        print(f"Error occurred: {e}")
    finally:
        conn.close()


add_missing_column()


@app.route('/logout')
def logout():
    
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)

