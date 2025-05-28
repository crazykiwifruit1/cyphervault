from flask import Flask, render_template, request, url_for, redirect, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# Import your strength module functions
from strength import entropy, checksubstring, generate_memorable_password

# Initialize Flask app
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "supersecretkey" # Make this a strong, truly secret key in production

# Initialize database and login manager
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login_page" # Changed to avoid conflict with /login API endpoint

# --- Models ---
class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)

class PasswordProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    profile_name = db.Column(db.String(250), nullable=False)
    profile_username = db.Column(db.String(250), nullable=False)
    profile_password = db.Column(db.String(250), nullable=False) # WARNING: Encrypt this in a real app!
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user = db.relationship('Users', backref=db.backref('password_profiles', lazy=True))

# --- Database Initialization (ensure all models are defined before create_all) ---
with app.app_context():
    db.create_all()

# --- Flask-Login User Loader ---
@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

# --- Helper Function for JSON Errors ---
def err(msg, code=400):
    return jsonify(success=False, message=msg), code

# --- API Endpoints (for Electron's fetch calls) ---

@app.route('/api/register', methods=["POST"])
def api_register():
    # Expect JSON data from Electron's fetch
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return err("Username and password are required.", 400)

    if Users.query.filter_by(username=username).first():
        return err("Username already taken!", 409) # 409 Conflict

    hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
    new_user = Users(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify(success=True, message="Registration successful."), 201 # 201 Created

@app.route("/api/login", methods=["POST"])
def api_login():
    # Expect JSON data from Electron's fetch
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return err("Username and password are required.", 400)

    user = Users.query.filter_by(username=username).first()

    if user and check_password_hash(user.password, password):
        login_user(user) # Log in the user with Flask-Login
        return jsonify(success=True, message="Login successful."), 200
        print("login successful")
    else:
        return err("Invalid username or password.", 401) # 401 Unauthorized

@app.route("/api/logout")
@login_required
def api_logout():
    logout_user()
    return jsonify(success=True, message="Logged out successfully."), 200


@app.route('/api/profile/store', methods=['POST'])
@login_required
def api_store_profile():
    data = request.get_json()
    profile_name = data.get('profile') # Corrected key name from 'profile_name' in HTML fetch to 'profile'
    profile_username = data.get('username')
    profile_password = data.get('password')

    if not profile_name or not profile_username or not profile_password:
        return err("All fields are required!", 400)

    # Check if a profile with the same name already exists for the current user
    existing_profile = PasswordProfile.query.filter_by(
        profile_name=profile_name,
        user_id=current_user.id
    ).first()

    if existing_profile:
        return err(f"Profile with name '{profile_name}' already exists for this user.", 409) # 409 Conflict

    new_profile = PasswordProfile(
        profile_name=profile_name,
        profile_username=profile_username,
        profile_password=profile_password, # WARNING: Encrypt this in a real app!
        user_id=current_user.id
    )
    db.session.add(new_profile)
    db.session.commit()
    return jsonify(success=True, message="Account stored securely."), 201

@app.route('/api/profile/<string:profile_name>', methods=['DELETE'])
@login_required
def api_delete_profile(profile_name):
    profile_to_delete = PasswordProfile.query.filter_by(
        profile_name=profile_name,
        user_id=current_user.id
    ).first()

    if profile_to_delete:
        db.session.delete(profile_to_delete)
        db.session.commit()
        return jsonify(success=True, message=f"Profile '{profile_name}' deleted successfully."), 200
    else:
        return err("Profile not found or unauthorized.", 404)

@app.route('/api/profiles', methods=['GET'])
@login_required
def api_profiles():
    user_profiles = PasswordProfile.query.filter_by(user_id=current_user.id).all()
    profiles_data = []
    for p in user_profiles:
        profiles_data.append({
            "id": p.id,
            "profile_name": p.profile_name,
            "profile_username": p.profile_username,
            "profile_password": p.profile_password # WARNING: Encrypt this in real app!
        })
    return jsonify(profiles=profiles_data), 200

# --- Password Checker & Generator API ---
@app.route("/checker")
def checker():
    pwd = request.args.get("pwd", "")
    if not pwd: return err("pwd parameter missing")
    return jsonify(
        success=True,
        entropy=entropy(pwd),
        matches=checksubstring(pwd, "SecLists/Passwords/Common-Credentials/hundredk.txt")
    )

@app.route("/generate/memorable-password")
def gen_pass():
    strength = int(request.args.get("strength", 5))
    length = request.args.get("length", type=int)
    if length is None:
        return err("length parameter missing or invalid.")
    return jsonify(success=True, password=generate_memorable_password(strength, length))

# --- HTML Page Routes (Electron navigates to these) ---

@app.route("/")
def home_page():
    
    return render_template("home.html")

@app.route("/login_page") 
def login_page():
    return render_template("login.html")

@app.route("/register_page") 
def register_page():
    return render_template("sign_up.html")

@app.route("/dashboard")
@login_required
def dashboard_page():
    return render_template("dashboard.html", username=current_user.username)

@app.route("/view_profiles")
@login_required
def view_profiles_page():
    return render_template("view_profiles.html")

@app.route("/settings")
@login_required
def settings_page():
    return render_template("settings.html")

@app.route("/account")
@login_required
def account_page():
    return render_template("account.html")

@app.route("/upload_profile_page") # New route for displaying the upload profile form
@login_required
def upload_profile_page():
    return render_template('upload_profile.html')

@app.route("/delete_account_page") # You might want a page to confirm deletion
@login_required
def delete_account_page():
    return render_template('delete_account.html') # Assuming you have this template

# --- Main run block ---
if __name__ == "__main__":
    app.run(port=5000, debug=True)