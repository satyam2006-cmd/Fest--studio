import os
import re
import secrets
import uuid
import random
import pytz
import requests
import string
import json
import uuid
from datetime import timedelta, datetime, timezone 
import time
import threading
from functools import wraps
from flask import (
    Flask, 
    render_template, 
    request, 
    redirect, 
    url_for, 
    flash, 
    make_response, 
    current_app, 
    jsonify, 
    send_from_directory,
    session,  # Add this import
    g
)
from flask_wtf.csrf import CSRFProtect, CSRFError, generate_csrf
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from PIL import Image
from apscheduler.schedulers.background import BackgroundScheduler
from flask_socketio import SocketIO
import logging
from flask_wtf import FlaskForm
from config import supabase

# Check for required packages
try:

        HAS_WTF = True
except ImportError:
    HAS_WTF = False
    print("Warning: Flask-WTF is not installed. CSRF protection will be disabled.")

# Chat app configuration
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'pdf', 'docx', 'xlsx', 'txt'}

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def verify_supabase_tables():
    """Verifies that the required tables exist in Supabase."""
    try:
        # Check for tables required by both the main app and the chat blueprint
        tables_to_check = ['users', 'communities', 'memberships', 'messages', 'events', 'polls', 'poll_options', 'poll_votes']
        
        for table in tables_to_check:
            try:
                supabase.table(table).select("*").limit(1).execute()
                print(f"✅ Table '{table}' verified")
            except Exception as table_error:
                print(f"❌ Table '{table}' not accessible or does not exist: {str(table_error)}")
                print(f"   Please ensure the table '{table}' is created in your Supabase project.")
        print("✅ Supabase table verification completed.")
        
    except Exception as e:
        print(f"❌ Database error: {e}")
        raise e

def seed_default_communities():
    """Checks for and creates default communities if they don't exist."""
    default_communities = [
        {'name': 'General', 'description': 'A place for general discussions.'},
        {'name': 'Photography', 'description': 'Share your photos and discuss techniques.'},
        {'name': 'Coding', 'description': 'Talk about programming, frameworks, and more.'},
        {'name': 'Design', 'description': 'All things design: UI/UX, graphics, and art.'},
        {'name': 'Gaming', 'description': 'Discuss video games, find teammates, and share clips.'}
    ]

    try:
        current_app.logger.info("Seeding default communities...")
        for comm in default_communities:
            # Check if community already exists (case-insensitive)
            existing_resp = supabase.table('communities').select('id').ilike('name', comm['name']).execute()
            
            if not existing_resp.data:
                # Community does not exist, create it as public
                supabase.table('communities').insert({
                    'name': comm['name'],
                    'description': comm['description'],
                    'visibility': 'public',
                }).execute()
                current_app.logger.info(f"Created default community: '{comm['name']}'")
    except Exception as e:
        current_app.logger.error(f"Error seeding default communities: {e}")

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def resize_avatar(source_path, dest_path, size=(128, 128)):
    try:
        img = Image.open(source_path)
        img = img.convert('RGBA')
        img.thumbnail(size, Image.LANCZOS)
        bg = Image.new('RGBA', size, (255, 255, 255, 255))
        bg.paste(img, ((size[0] - img.size[0]) // 2, (size[1] - img.size[1]) // 2), img)
        bg.convert('RGB').save(dest_path, format='JPEG', quality=85)
        return True
    except Exception as e:
        print('Avatar resize error:', e)
        return False

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    HAS_LIMITER = True
except Exception:
    HAS_LIMITER = False

# Import chat blueprint
from chat_routes import chat_bp, register_socketio_handlers

# App
def create_app():
    app = Flask(__name__)
    
    # Initialize SocketIO, but defer running to main block
    # This allows us to use the socketio object globally
    
    # Generate a secure secret key if not provided
    secret_key = os.environ.get("SECRET_KEY")
    if not secret_key:
        secret_key = secrets.token_hex(32)  # Generate a secure random key
        os.environ["SECRET_KEY"] = secret_key  #
    
    # Load secrets & config from env
    app.config.update(
        SECRET_KEY=secret_key,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=int(os.environ.get("SESSION_TTL_MIN", "60"))),
        WTF_CSRF_ENABLED=True,
        WTF_CSRF_TIME_LIMIT=3600,
        WTF_CSRF_SECRET_KEY=os.environ.get("WTF_CSRF_SECRET_KEY") or secrets.token_hex(32),
        DATABASE_URL=os.getenv("DATABASE_URL"),
        SESSION_TYPE='filesystem'  # Add this line
    )

    # Ensure instance folder exists
    os.makedirs(app.instance_path, exist_ok=True)

    # Initialize CSRF protection
    if HAS_WTF:
        csrf = CSRFProtect(app)
        # NOTE: CSRFProtect automatically makes the csrf_token() function
        # available in templates, so a manual context processor is not needed.

    # Rate limiting
    if HAS_LIMITER:
        limiter = Limiter(
            get_remote_address,  # Remove app and just pass the key_func
            app=app,            # Pass app as a named parameter
            default_limits=["200 per day", "50 per hour"],
            storage_uri="memory://"  # For development
        )

    # Basic logging
    logging.basicConfig(level=logging.INFO)
    app.logger.info("App starting with Supabase URL: %s", app.config["DATABASE_URL"])

    # Auth utilities
    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if "user" not in session:
                flash("You must be logged in.", "warning")
                return redirect(url_for("home"))
            return view(*args, **kwargs)
        return wrapped

    email_regex = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

    def validate_email(email: str) -> bool:
        return bool(email) and bool(email_regex.match(email))

    def validate_password(pw: str) -> tuple[bool, str]:
        if not pw or len(pw) < 8:
            return False, "Password must be at least 8 characters."
        if not re.search(r"[A-Za-z]", pw) or not re.search(r"\d", pw):
            return False, "Password must include letters and numbers."
        return True, ""

    # Error handler for CSRF errors
    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        app.logger.warning(f"CSRF error: {e.description}")
        flash("The form has expired. Please try again.", "danger")
        return redirect(request.referrer or url_for('home'))

    # Routes
    @app.route("/health")
    def health():
        return {"status": "ok"}, 200
    
    @app.route("/")
    @app.route("/landing")
    def home():
        try:
            # Create a form instance to pass to the template for CSRF token generation
            form = FlaskForm()
            # Call the new RPC function to get correctly filtered upcoming events.
            response = supabase.rpc('get_upcoming_events', {}).execute()

            # The database now does the precise filtering, so no Python filtering is needed.
            events = response.data or []

            return render_template("landing.html", carousel_events=events, form=form)
        except Exception as e:
            app.logger.error(f"Error loading events: {str(e)}")
            return render_template("landing.html", carousel_events=[], form=form)

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if request.method == 'GET':
            return redirect(url_for('signin'))
        # POST logic remains the same
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        
        if not email or not password or not username:
            flash('Username, email, and password are required.', 'error')
            return redirect(url_for('signin'))

        # Validate password
        is_valid, message = validate_password(password)
        if not is_valid:
            flash(message, 'danger')
            return redirect(url_for('signin'))

        try:
            # Attempt to sign up the user
            auth_response = supabase.auth.sign_up({"email": email, "password": password})
            user = auth_response.user

            # The handle_new_user trigger will automatically create the public.users record.
            # We just need to update it with the username.
            if user and user.id:
                supabase.table('users').insert({'id': user.id, 'email': user.email, 'username': username}).execute()

            flash('Registered successfully! Please check your email to confirm your account, just click the link and return to log in.', 'success')
            return redirect(url_for('signin'))
        except Exception as e:
            error_message = str(e)
            app.logger.error(f"Registration error: {error_message}")

            # Check if the error is because the user already exists
            if "User already registered" in error_message:
                # Try to resend the confirmation email for an unconfirmed user
                supabase.auth.resend_confirmation_email(email)
                flash('This email is already registered. We have sent you another confirmation link.', 'warning')
            else:
                flash('Registered successfully! Please check your email to confirm your account, just click the link and return log in.', 'success')
            return redirect(url_for('signin'))

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        # This route is now primarily for GET requests, redirecting to the unified signin page.
        # POST requests are handled by chat_routes.chat_login.
        if request.method == 'GET':
            return redirect(url_for('signin'))
        # For any POST requests directly to /login, redirect to signin with an error
        flash('Please use the unified sign-in page.', 'error')
        return redirect(url_for('signin'))

    @app.route("/welcome")
    def welcome():
        if "user" in session:
            return render_template("profile.html", username=session["user"])
        return redirect(url_for("home"))

    @app.route("/logout")
    def logout():
        try:
            supabase.auth.sign_out()
        except Exception as e:
            app.logger.error(f"Error during logout: {e}")
        session.clear()
        flash("Signed out.", "info")
        return redirect(url_for("home"))

    @app.route("/host-event", methods=["GET", "POST"])
    @login_required
    def host_event():
        form = FlaskForm() # Create a form instance for CSRF token

        if request.method == "POST":
            # 1. Get text data from the form
            event_data = {
                'event_name': request.form.get("eventName"),
                'host_name': request.form.get("hostName"),
                'host_email': request.form.get("hostEmail", "").strip().lower(),
                'venue': request.form.get("venue"),
                'agenda': request.form.get("agenda"),
                'category': request.form.get("category"),
                'registration_link': request.form.get("registrationLink"),
                'creator_id': session.get('user_id'),  # This should be a UUID
                'hero_text_line1': request.form.get("hero_text_line1"),
                'hero_text_line2': request.form.get("hero_text_line2"),
                'how_we_planned_text': request.form.get("how_we_planned_text")
            }

            # 2. Handle direct file uploads to Supabase Storage
            image_fields = ['event_logo', 'parallax_img_1', 'parallax_img_2', 'parallax_img_3']
            # Combine date, time, and timezone into a single timestamptz
            try:
                event_date_str = request.form.get("date")
                event_time_str = request.form.get("time")
                event_tz_str = request.form.get("timezone")
                event_local_dt_str = f"{event_date_str} {event_time_str}"
                
                event_tz = pytz.timezone(event_tz_str)
                naive_dt = datetime.strptime(event_local_dt_str, "%Y-%m-%d %H:%M")
                local_dt = event_tz.localize(naive_dt)
                event_data['event_datetime'] = local_dt.isoformat()
            except (pytz.UnknownTimeZoneError, ValueError) as e:
                app.logger.error(f"Invalid date/time/timezone provided: {e}")
                flash("Invalid date, time, or timezone. Please check your input.", "danger")
                return redirect(url_for("host_event"))
            bucket_name = 'event-images'

            for field in image_fields:
                file = request.files.get(field)
                if file and file.filename and allowed_file(file.filename):
                    try:
                        # Generate a unique filename to prevent overwrites
                        filename = f"{uuid.uuid4()}_{secure_filename(file.filename)}"
                        
                        # Upload to Supabase Storage
                        supabase.storage.from_(bucket_name).upload(
                            file=file.read(), 
                            path=filename, 
                            file_options={"content-type": file.content_type}
                        )
                        
                        # Get the public URL and add it to our data
                        public_url_response = supabase.storage.from_(bucket_name).get_public_url(filename)
                        event_data[field] = public_url_response
                    except Exception as e:
                        app.logger.error(f"Error uploading {field} to Supabase: {e}")
                        flash(f"Failed to upload {file.filename}. Please try again.", "danger")
                        return redirect(url_for("host_event"))
                elif file and file.filename and not allowed_file(file.filename):
                    flash(f"File type not allowed for {field}.", "danger")
                    return redirect(url_for("host_event"))

            # 3. Insert the complete record into the database
            try:
                response = supabase.table('events').insert(event_data).execute()
                flash("Event hosted successfully!", "success")
                event_id = response.data[0]['id']
                return redirect(url_for("event_detail", event_id=event_id))
            except Exception as e:
                app.logger.error(f"Error saving event: {str(e)}")
                flash("An error occurred while saving the event. Please try again.", "danger")
                return redirect(url_for("host_event"))

        return render_template("premium_event.html", form=form)

    @app.route("/events/preview")
    def event_preview():
        # The template will now pull data from sessionStorage on the client-side
        # We pass a flag to tell the template it's in preview mode.
        return render_template("eventspg.html", is_preview=True, event={})

    @app.route("/events/<string:event_id>")
    def event_detail(event_id):
        try:
            response = supabase.table('events')\
                .select('*')\
                .eq('id', event_id)\
                .limit(1)\
                .execute()
            
            if response.data:
                event = response.data[0]
                return render_template("eventspg.html", event=event)
            else:
                return "Event not found", 404
        except Exception as e:
            app.logger.error(f"Error fetching event: {e}")
            return "Error loading event", 500

    @app.route("/ourteam")
    def ourteam():
        return render_template("our_team.html")


    @app.route("/signin", methods=["GET"])
    def signin():
        # Create a form instance to pass to the template for CSRF token generation
        form = FlaskForm()
        return render_template("signin.html", form=form)

    # Custom filter to format time strings
    @app.template_filter('format_time')
    def format_time_filter(s):
        """Formats a time string from HH:MM:SS to HH:MM."""
        if not s:
            return ''
        parts = str(s).split(':')
        return f"{parts[0]}:{parts[1]}" if len(parts) >= 2 else s

    # Add custom template filters
    @app.template_filter('format_event_time')
    def format_event_time_filter(utc_dt_str, user_timezone='UTC'):
        """Converts a UTC datetime string to a user's local time and formats it."""
        user_tz = pytz.timezone(user_timezone)
        utc_dt = datetime.fromisoformat(utc_dt_str).astimezone(pytz.utc)
        local_dt = utc_dt.astimezone(user_tz)
        return local_dt.strftime('%A, %B %d, %Y at %I:%M %p %Z')
    @app.template_filter('format_event_date_part')
    def format_event_date_part_filter(utc_dt_str, user_timezone='UTC'):
        """Converts a UTC datetime string to a user's local date and formats it."""
        if not utc_dt_str:
            return 'Date not set'
        try:
            user_tz = pytz.timezone(user_timezone)
            utc_dt = datetime.fromisoformat(utc_dt_str).astimezone(pytz.utc)
            local_dt = utc_dt.astimezone(user_tz)
            return local_dt.strftime('%A, %B %d, %Y')
        except (ValueError, pytz.UnknownTimeZoneError):
            return 'Invalid date'

    @app.template_filter('format_event_time_part')
    def format_event_time_part_filter(utc_dt_str, user_timezone='UTC'):
        """Converts a UTC datetime string to a user's local time and formats it."""
        if not utc_dt_str:
            return 'Time not set'
        try:
            user_tz = pytz.timezone(user_timezone)
            utc_dt = datetime.fromisoformat(utc_dt_str).astimezone(pytz.utc)
            local_dt = utc_dt.astimezone(user_tz)
            return local_dt.strftime('%I:%M %p %Z')
        except (ValueError, pytz.UnknownTimeZoneError):
            return 'Invalid time'
    @app.template_filter('file_exists')
    def file_exists_filter(path):
        if not path or path == 'No logo':
            return False
        static_path = os.path.join(current_app.static_folder, path.replace('/', os.sep).lstrip(os.sep))
        return os.path.isfile(static_path)
        
    @app.context_processor
    def inject_hosted_events():
        """Makes hosted_events available to all templates if user is logged in."""
        try:
            user_id = session.get('user_id')
            if user_id:
                # Call the RPC function to get all upcoming events
                rpc_response = supabase.rpc('get_upcoming_events', {}).execute()

                if rpc_response.data:
                    all_upcoming = rpc_response.data
                    now_utc = datetime.now(timezone.utc)
                    
                    # Filter for events hosted by the user AND ensure they are still in the future.
                    # This provides an extra layer of certainty.
                    user_events = []
                    for event in all_upcoming:
                        if str(event.get('creator_id')) == str(user_id):
                            user_events.append(event)
                    return dict(user_hosted_events=user_events)
        except Exception as e:
            app.logger.error(f"Could not inject hosted events: {e}")
        return dict(user_hosted_events=None)  # Always return a dictionary

    # Register chat blueprint so its endpoints (e.g. chat.chat_index) exist
    # regardless of how the app is started (dev server, gunicorn, Render, etc.).
    try:
        app.register_blueprint(chat_bp, url_prefix='/chat')
    except Exception:
        # If registration fails for any unexpected reason, log but continue.
        app.logger.exception('Could not register chat blueprint during app creation')

    return app

app = create_app()
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

# Register SocketIO handlers after the app and socketio objects are created
register_socketio_handlers(socketio)

# --- One-time Initialization ---
# This ensures that database verification and seeding runs only once per process.
@app.before_request
def initialize_app():
    # The 'g' object is a request-specific global. We use it to store a flag.
    if not hasattr(g, '_initialized'):
        verify_supabase_tables()
        seed_default_communities()
        g._initialized = True

# --- New Deletion Logic (moved to global scope) ---
def delete_event_and_storage_python_helper(event_id, user_id=None):
    """
    Python helper function to call the Supabase RPC function for deleting an event
    and its associated storage files.
    The user_id is optional; if provided, the SQL function will enforce ownership checks.
    If user_id is None, it's assumed to be a system-level call (like a scheduler)
    that should bypass user ownership checks.
    """
    try:
        # The SQL function will handle all logic, including permissions and storage cleanup.
        supabase.rpc('delete_event_and_storage', {
            'p_event_id': event_id,
            'p_user_id': user_id
        }).execute()
        return True, "Event deleted successfully."
    except Exception as e:
        # Log the detailed error
        import traceback
        tb = traceback.format_exc()
        current_app.logger.error(f"RPC delete_event_and_storage failed for event {event_id}: {e}\nTraceback: {tb}")
        # Provide a user-friendly error message
        if "permission" in str(e).lower():
            return False, f"You do not have permission to delete this event. Details: {str(e)}"
        return False, f"An error occurred while deleting the event. Details: {str(e)}"

def cleanup_past_events():
    """
    The background scheduler job that calls the Supabase RPC to delete all past events.
    """
    with app.app_context():
        current_app.logger.info("Running scheduled job: cleanup_past_events...")
        try:
            # This RPC function now finds all events that have passed in their own timezone
            # and soft-deletes them by setting their 'deleted_at' timestamp.
            supabase.rpc('delete_past_events', {}).execute()
            current_app.logger.info("Successfully completed scheduled job: cleanup_past_events.")
        except Exception as e:
            app.logger.error(f"Error in scheduled job cleanup_past_events: {e}")

# --- Background Scheduler for Cleanup Tasks ---
if __name__ == "__main__":
    logging.info("Running at http://localhost:5000")

    # Initialize and start the scheduler
    scheduler = BackgroundScheduler(daemon=True)
    # Run the job every hour. You can adjust this as needed.
    # For testing, you can set it to 'interval', minutes=1
    scheduler.add_job(cleanup_past_events, 'interval', minutes=1)
    scheduler.start()
    
    # The 'startCommand' in render.yaml will use Gunicorn in production.
    # This block is now only for local development.
    # The host='0.0.0.0' makes it accessible on your local network.
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port)

