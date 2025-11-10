from flask import Blueprint, render_template, request, redirect, url_for, session, flash, send_from_directory, g, current_app, make_response, jsonify
from flask_socketio import join_room, leave_room, emit
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from PIL import Image
import qrcode
import os
import uuid
import random
import string
from datetime import datetime
from functools import wraps
from config import supabase  # Import the Supabase client
# Import SQLAlchemy db object and models from the main app

# Import CSRF protection
try:
    from flask_wtf import FlaskForm
    HAS_WTF = True
except ImportError:
    HAS_WTF = False

# Create Blueprint
chat_bp = Blueprint('chat', __name__, template_folder='templates/chat', static_folder='static')

# Use the Supabase client as the database connection
def get_chat_db():
    return supabase

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            next_url = request.url
            # Redirect to main app signin to avoid auth clashes
            return redirect(url_for('signin', next=next_url, _external=True))
        
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

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

@chat_bp.route('/')
@login_required
def chat_index():
    db = get_chat_db()
    # Create a form instance to pass to the template for CSRF token generation
    form = FlaskForm()

    user_id = session.get('user_id')
    
    try:
        user_resp = db.table('users').select('*').eq('id', user_id).single().execute()
        user = user_resp.data

        # Get communities user has joined
        joined_resp = db.rpc('get_joined_communities', {'p_user_id': user_id}).execute()
        joined_communities = joined_resp.data or []

        # Get communities created by the user
        hosted_resp = db.rpc('get_hosted_communities', {'p_user_id': user_id}).execute()
        hosted_communities = hosted_resp.data or []

    except Exception as e:
        current_app.logger.error(f"Error fetching chat_index data: {e}")
        flash("Could not load your dashboard. Please try again later.", "error")
        user = None
        joined_communities = []
        hosted_communities = []

    # The user object from Supabase auth might be different.
    # Let's create a user object for the template.
    template_user = None
    if user:
        template_user = user
    elif 'user' in session:
        template_user = {
            'id': session['user'].get('id'),
            'email': session['user'].get('email'),
            'username': session['user'].get('email') # Fallback
        }

    return render_template('chat/index.html',
                         user=template_user,
                         joined_communities=joined_communities,
                         hosted_communities=hosted_communities,
                         form=form)

from flask_wtf.csrf import generate_csrf

@chat_bp.route('/logout')
def chat_logout():
    session.clear()
    flash('You have been logged out', 'success')
    return redirect(url_for('signin'))

@chat_bp.route('/login', methods=['POST'])
def chat_login(): # This route handles login POST requests from signin.html
    """Handles login for the chat system, accepting email or username."""
    login_input = request.form.get('login_input', '').strip()
    password = request.form.get('password', '') # Default to home route
    next_url = request.form.get('next') or url_for('home')

    if not login_input or not password:
        flash('Email/Username and password are required.', 'danger')
        return redirect(url_for('signin'))

    email = login_input
    # Check if the input is a username and not an email
    if '@' not in login_input:
        try:
            # Find the user's email from their username in the public.users table
            user_profile_resp = supabase.table('users').select('email').eq('username', login_input).single().execute()
            if user_profile_resp.data:
                email = user_profile_resp.data['email']
            else:
                flash('Username not found. Please check your username or use your email.', 'danger')
                return redirect(url_for('signin'))
        except Exception as e:
            current_app.logger.error(f"Username lookup error: {e}")
            flash('An error occurred. Please try again.', 'danger')
            return redirect(url_for('signin'))

    # Proceed with login using the email
    try:
        auth_response = supabase.auth.sign_in_with_password({
            "email": email,
            "password": password
        })
        user_data = auth_response.user

        # Fetch user profile to get username
        user_profile = {}
        if user_data:
            # Use .execute() instead of .single().execute() to avoid an error if the user profile doesn't exist yet.
            # This makes the login process more resilient.
            profile_resp = supabase.table('users').select('username').eq('id', user_data.id).execute()
            if profile_resp.data:
                # The result is a list, so we take the first item.
                user_profile = profile_resp.data[0]

        session['user'] = {
            'id': user_data.id,
            'email': user_data.email,
            'username': user_profile.get('username')
        }
        session['user_id'] = user_data.id
        session['access_token'] = auth_response.session.access_token
        return redirect(next_url)
    except Exception as e:
        error_message = str(e)
        current_app.logger.error(f"Login error: {error_message}")
        # Check for Supabase's specific email confirmation error
        if "Email not confirmed" in error_message:
            flash('Your email is not confirmed. Please check your inbox for a verification link.', 'warning')
        else:
            flash('Invalid username or password.', 'danger')
        return redirect(url_for('signin'))

@chat_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    db = get_chat_db()
    user_id = session['user_id']
    try:
        user_resp = db.table('users').select('*').eq('id', user_id).single().execute()
        user = user_resp.data
    except Exception as e:
        user = None
        flash(f"Error loading profile: {e}", "error")
        return redirect(url_for('chat.chat_index'))

    if request.method == 'POST':
        new_timezone = request.form.get('timezone')
        try:
            db.table('users').update({'timezone': new_timezone}).eq('id', user_id).execute()
            # Update the session as well
            if 'user' in session:
                session['user']['timezone'] = new_timezone
                session.modified = True
            flash('Timezone updated successfully!', 'success')
            return redirect(url_for('chat.profile'))
        except Exception as e:
            flash(f"Error updating timezone: {e}", "error")
        flash(f"Error loading profile: {e}", "error")
        return redirect(url_for('chat.chat_index'))

    # Create a response object to add cache-control headers
    response = make_response(render_template('profile.html', user=user))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    return response

@chat_bp.route('/communities')
@login_required
def communities():
    db = get_chat_db()
    # Create a form instance to pass to the template for CSRF token generation
    form = FlaskForm()

    user_id = session['user_id']
    try:
        # Fetch user, but don't use .single() to prevent errors if the profile is momentarily missing.
        user_resp = db.table('users').select('*').eq('id', user_id).execute()
        # If data exists, take the first item; otherwise, user is None.
        user = user_resp.data[0] if user_resp.data else None

        # Use an RPC function to get communities with member status
        comm_resp = db.rpc('get_all_communities', {'p_user_id': user_id}).execute()
        communities_list = comm_resp.data or []

        return render_template('chat/com.html',
                            user=user,
                            communities=communities_list,
                            form=form)

    except Exception as e:
        user = None
        communities_list = []
        flash(f'Error loading communities: {str(e)}', 'error')
        import traceback
        print(f"Error in communities view: {str(e)}\n{traceback.format_exc()}")
        return redirect(url_for('chat.chat_index'))

@chat_bp.route('/join_private', methods=['POST'])
@login_required
def join_private():
    db = get_chat_db()
    # The CSRF token is validated from the form, no need to generate it here.
    # csrf_token = generate_csrf()
    try:
        code = request.form.get('code', '').strip().upper()
        community_id = request.form.get('community_id')
        
        if not code and not community_id:
            flash('Please enter a join code or select a community', 'error')
            return redirect(url_for('chat.communities'))
            
        # Find community by join code or ID
        query = db.table('communities').select('*').eq('visibility', 'private')
        if community_id:
            query = query.eq('id', community_id)
            if code:
                query = query.eq('join_code', code)
        else:
            query = query.eq('join_code', code)

        community_resp = query.single().execute()
        community = community_resp.data

        if not community:
            flash('Invalid join code or community not found', 'error')
            return redirect(url_for('chat.communities'))
            
        # Check if already a member
        user_id = session['user_id']
        existing_resp = db.table('memberships').select('user_id').eq('user_id', user_id).eq('community_id', community['id']).execute()
        existing = existing_resp.data

        if existing:
            flash('You are already a member of this community', 'info')
            return redirect(url_for('chat.community', cid=community['id']))
            
        # Add user as member
        db.table('memberships').insert({
            'user_id': user_id,
            'community_id': community['id'],
            'is_admin': False
        }).execute()

        flash('Successfully joined the community!', 'success')
        return redirect(url_for('chat.community', cid=community['id']))
        
    except Exception as e:
        flash(f'Error joining community: {str(e)}', 'error')
        print(f"Error in join_private: {str(e)}")
        return redirect(url_for('chat.communities'))
            
@chat_bp.route('/join_public/<string:cid>', methods=['POST'])
@login_required
def join_public(cid):
    db = None
    # The CSRF token is validated from the form, no need to generate it here.
    # csrf_token = generate_csrf()
    try:
        db = get_chat_db()
        user_id = session['user_id']
        
        # Verify community exists and is public
        community_resp = db.table('communities').select('*').eq('id', cid).eq('visibility', 'public').single().execute()
        community = community_resp.data

        if not community:
            flash('Community not found or is private. Please use the private join if you have a code.', 'error')
            return redirect(url_for('chat.communities'))
            
        # Check if already a member
        existing_resp = db.table('memberships').select('user_id').eq('user_id', user_id).eq('community_id', cid).execute()
        existing = existing_resp.data

        if existing:
            flash('You are already a member of this community', 'info')
            return redirect(url_for('chat.community', cid=cid))
            
        # Add user as member
        db.table('memberships').insert({
            'user_id': user_id,
            'community_id': cid,
            'is_admin': False
        }).execute()

        flash('Successfully joined the community!', 'success')
        return redirect(url_for('chat.community', cid=cid))
        
    except Exception as e:
        flash(f'Error joining community: {str(e)}', 'error')
        print(f"Error in join_public: {str(e)}")
        return redirect(url_for('chat.communities'))

@chat_bp.route('/create_community', methods=['GET', 'POST'])
@login_required
def create_community():
    # Use a real FlaskForm instance to handle CSRF protection.
    form = FlaskForm()
    if request.method == 'POST':
        db = get_chat_db()
        try:
            name = request.form.get('name', '').strip()
            description = request.form.get('description', '').strip()
            visibility = 'private' if request.form.get('is_private') == '1' else 'public'
            
            if not name:
                flash('Community name is required', 'error')
                return redirect(url_for('chat.create_community'))
                
            # Check if community name already exists (case-insensitive)
            # Supabase text search is case-sensitive by default, use ilike for case-insensitivity
            existing_resp = db.table('communities').select('id').ilike('name', name).execute()
            if existing_resp.data:
                flash('A community with this name already exists', 'error')
                return redirect(url_for('chat.create_community'))
            
            # Generate a join code for private communities
            join_code = None
            if visibility == 'private':
                join_code = str(uuid.uuid4().hex)[:8].upper()
            
            # Create the community
            community_resp = db.table('communities').insert({
                'name': name,
                'description': description,
                'visibility': visibility,
                'join_code': join_code,
                'creator_id': session['user_id']
            }).execute()
            community_id = community_resp.data[0]['id']

            # Add creator as a member and admin in a single transaction
            db.table('memberships').insert({
                'user_id': session['user_id'],
                'community_id': community_id,
                'is_admin': True
            }).execute()

            
            # Generate QR code for private communities
            if visibility == 'private' and join_code:
                qr_dir = os.path.join('static', 'qr')
                os.makedirs(qr_dir, exist_ok=True)
                qr_path = os.path.join(qr_dir, f"{join_code}.png")
                
                # Create QR code
                qr = qrcode.QRCode(
                    version=1,
                    error_correction=qrcode.constants.ERROR_CORRECT_L,
                    box_size=10,
                    border=4,
                )
                qr.add_data(join_code)
                qr.make(fit=True)
                img = qr.make_image(fill_color="black", back_color="white")
                img.save(qr_path)
            
            flash('Community created successfully!', 'success')
            
            # Redirect to the community chat page
            return redirect(url_for('chat.community', cid=community_id))
            
        except Exception as e:
            flash(f'An error occurred while creating the community: {str(e)}', 'error')
            print(f"Error creating community: {str(e)}")
            import traceback
            traceback.print_exc()
            return redirect(url_for('chat.create_community')) # Ensure redirect on error
    
    # For GET request
    return render_template('chat/create_community.html', form=form)

@chat_bp.route('/delete_community/<string:cid>', methods=['POST'])
@login_required
def delete_community(cid):
    db = get_chat_db()
    try:
        # Verify user is the creator
        community_resp = db.table('communities').select('creator_id').eq('id', cid).single().execute()
        community = community_resp.data
        if not community or str(community['creator_id']) != str(session['user_id']):
            flash('You do not have permission to delete this community.', 'error')
            return redirect(url_for('chat.communities'))

        # RLS policies should handle cascading deletes if set up correctly.
        # Explicitly deleting from related tables first is safer if cascades aren't guaranteed.
        db.table('memberships').delete().eq('community_id', cid).execute()
        db.table('messages').delete().eq('community_id', cid).execute()
        # Polls and related data will be deleted by cascade if set up in DB.
        db.table('communities').delete().eq('id', cid).execute()
        
        flash('Community deleted successfully.', 'success')
        
    except Exception as e:
        flash(f'An error occurred while deleting the community: {str(e)}', 'error')
        print(f"Error deleting community: {str(e)}")
    
    return redirect(url_for('chat.chat_index'))

@chat_bp.route('/delete_hosted_event/<string:event_id>', methods=['POST'])
@login_required
def delete_hosted_event(event_id):
    # This form object is needed for CSRF validation
    form = FlaskForm()
    # Redirect to the previous page by default, or home if referrer is missing.
    redirect_url = request.referrer or url_for('home')

    if form.validate_on_submit():
        user_id = session['user_id']
        # Call the centralized deletion function from app.py
        with current_app.app_context():
            from app import delete_event_and_storage_python_helper
            success, message = delete_event_and_storage_python_helper(event_id, user_id)

        if success:
            flash(f"Event deleted: {message}", 'success')
        else:
            flash(f"Event deletion failed: {message}", 'danger')
            current_app.logger.error(f"Event deletion failed. {message}")
    else:
        # This will catch the CSRF error if it occurs
        flash('The form has expired or is invalid. Please try again.', 'danger')
    
    return redirect(redirect_url)

@chat_bp.route('/leave_community/<string:cid>', methods=['POST'])
@login_required
def leave_community(cid):
    db = get_chat_db()
    try:
        user_id = session['user_id']
        
        # Verify user is a member but not the creator
        community_resp = db.table('communities').select('creator_id').eq('id', cid).single().execute()
        community = community_resp.data
        if not community:
            flash('Community not found.', 'error')
            return redirect(url_for('chat.communities'))
            
        if str(community['creator_id']) == str(user_id):
            flash('As the host, you must delete the community instead of leaving.', 'error')
            return redirect(url_for('chat.communities'))

        db.table('memberships').delete().match({'user_id': user_id, 'community_id': cid}).execute()

        flash('You have left the community.', 'success')
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
    return redirect(url_for('chat.chat_index'))

@chat_bp.route('/community/<string:cid>')
@login_required
def community(cid):
    db = None
    db = get_chat_db()
    user_id = session.get('user_id')
    try:
        # Use RPC to get all community data in one go
        # Now that the SQL function returns SETOF communities with LIMIT 1,
        # the Python client will return a single dictionary or None.
        community_resp = db.table('communities').select('*').eq('id', cid).single().execute()
        community = community_resp.data

        if not community: # If community is None, it means no record was found
            flash('Community not found', 'error')
            return redirect(url_for('chat.communities'))
        # Fetch members
        members_resp = db.table('memberships').select('is_admin, users(id, username, avatar)').eq('community_id', community['id']).order('joined_at', desc=False).execute()
        members = [dict(m['users'], **{'is_admin': m['is_admin']}) for m in members_resp.data]

        # Fetch messages
        messages_resp = db.table('messages').select('*, user:users(username, avatar, email), replied_to:reply_to_id(text, user:users(id, username, email))').eq('community_id', cid).order('created_at', desc=False).limit(100).execute()
        messages_list = _process_messages(messages_resp.data, user_id)

        # Fetch polls
        polls_resp = db.rpc('get_polls_for_community', {'p_community_id': cid, 'p_user_id': user_id}).execute()
        polls_list = polls_resp.data or []

        # Combine and sort messages and polls by their creation timestamp
        all_content = sorted(messages_list + polls_list, key=lambda x: x.get('created_at'))

        user_resp = db.table('users').select('*').eq('id', user_id).single().execute()
        user_data = user_resp.data

        is_admin = any(m['is_admin'] for m in members if str(m['id']) == str(user_id))

        return render_template('chat/chat.html',
                            community=community,
                            messages=all_content, # Pass combined and sorted content
                            members=members,
                            user=user_data,
                            is_admin=is_admin)
                            

    except Exception as e:

        import traceback
        print(f"Error in community view: {str(e)}\n{traceback.format_exc()}")
        flash(f'Error loading community: {str(e)}', 'error')
        return redirect(url_for('chat.communities'))

def _process_messages(raw_messages, current_user_id=None):
    """Helper function to safely process raw message data from Supabase."""
    processed_list = []
    if not raw_messages:
        return processed_list

    for m in raw_messages:
        msg_dict = {
            'type': 'message',
            'id': m.get('id'),
            'user_id': m.get('user_id'),
            # Use username, fallback to email from the user relation, then a default
            'username': m.get('user', {}).get('username') or (m.get('user', {}).get('email', 'User').split('@')[0]),
            'is_edited': m.get('updated_at') is not None and m.get('updated_at') != m.get('created_at'),
            'user_avatar': m.get('user', {}).get('avatar'),
            'text': m.get('text'),
            'created_at': m.get('created_at'),
            'reply_to_id': m.get('reply_to_id'),
            'replied_to_username': None,
            'replied_to_text': None,
        }
        
        replied_to_data = m.get('replied_to')
        # Defensively handle if replied_to_data itself is a list
        if isinstance(replied_to_data, list) and replied_to_data:
            replied_to_data = replied_to_data[0]

        if replied_to_data:
            msg_dict['replied_to_text'] = replied_to_data.get('text')
            user_field = replied_to_data.get('user')

            # Defensively handle the case where the nested user might be a list
            # This converts the list to a dictionary before we use it.
            if isinstance(user_field, list) and user_field:
                user_field = user_field[0]

            if isinstance(user_field, dict): # Now process the user object
                replied_to_username = user_field.get('username') or (user_field.get('email', 'User').split('@')[0])
                # Check if the reply is to the current user
                if current_user_id and user_field.get('id') and str(user_field.get('id')) == str(current_user_id):
                    replied_to_username = 'you'
                msg_dict['replied_to_username'] = replied_to_username

        processed_list.append(msg_dict)
    return processed_list

# SocketIO handlers - simplified like your original code
clients = {}
from flask import request as flask_request

def register_socketio_handlers(socketio_instance):

    @socketio_instance.on('join')
    def on_join(data):
        sid = flask_request.sid
        user_id = session.get('user_id')
        community_id = data.get('community_id') # Treat as a string (UUID)
        room = f'community_{community_id}'

        user_info = session.get('user', {})
        username = user_info.get('username') or user_info.get('email') # Default to email

        # Try to get a real username from the DB
        with current_app.app_context():
            try:
                # Use .execute() instead of .single() to prevent errors if the profile is momentarily missing.
                user_profile_resp = supabase.table('users').select('username').eq('id', user_id).execute()
                # Safely access the data if it exists
                if user_profile_resp.data and user_profile_resp.data[0].get('username'):
                    username = user_profile_resp.data[0]['username']
            except Exception:
                pass # Fallback to email if DB query fails
        
        join_room(room)
        clients[sid] = {'user_id': user_id, 'username': username, 'community_id': community_id}
        
        # Broadcast updated member list
        online_members = [{'username': c['username']} for c in clients.values() if c.get('community_id') == community_id]
        socketio_instance.emit('members_update', online_members, room=room)
        socketio_instance.emit('user_status', 
             {'message': f'{username} has joined the chat.'}, 
             room=f'community_{community_id}')

    @socketio_instance.on('send_message')
    def on_message(data):
        sid = flask_request.sid
        user_id = session.get('user_id')
        if not user_id:
            return
            
        community_id = data.get('community_id') # Treat as a string (UUID)
        text = data.get('text','').strip()
        reply_to_id = data.get('reply_to_id')

        if not text: return
            
        ts = datetime.utcnow().isoformat() + "+00:00" # ISO 8601 with timezone for postgres
        room = f'community_{community_id}'

        with current_app.app_context():
            try:
                # Get user info
                user_resp = supabase.table('users').select('username, avatar').eq('id', user_id).single().execute()
                user = user_resp.data or {}
                
                # Get username, or splice it from the email in the session as a fallback
                username = user.get('username')
                if not username:
                    email = session.get('user', {}).get('email', 'Anonymous')
                    username = email.split('@')[0]

                # Insert message
                insert_data = {
                    'community_id': community_id,
                    'user_id': user_id,
                    'text': text,
                    'created_at': ts
                }
                if reply_to_id:
                    insert_data['reply_to_id'] = reply_to_id

                msg_resp = supabase.table('messages').insert(insert_data).execute()
                message = msg_resp.data[0]

                # Fetch reply context for broadcasting
                reply_context = None
                if reply_to_id:
                    # Use .single() to ensure we get one object
                    reply_resp = supabase.table('messages').select('text, user:users(username, email)').eq('id', reply_to_id).single().execute()
                    if reply_resp.data:
                        replied_user = reply_resp.data.get('user', {})
                        replied_username = replied_user.get('username') or (replied_user.get('email', 'User').split('@')[0])
                        reply_context = {'username': replied_username, 'text': reply_resp.data['text']}
            except Exception as e:
                current_app.logger.error(f"Error sending message: {e}")
                return

            socketio_instance.emit('new_message', {
                'id': message['id'],
                'user_id': user_id,
                'username': username, 
                'text': text, 
                'created_at': ts, # Use created_at for consistency with historical messages
                'reply_context': reply_context
            }, to=room)

    @socketio_instance.on('edit_message')
    def on_edit_message(data):
        user_id = session.get('user_id')
        if not user_id: return

        message_id = data.get('message_id')
        new_text = data.get('text', '').strip()
        community_id = data.get('community_id')
        room = f'community_{community_id}'

        if not new_text or not message_id:
            return

        with current_app.app_context():
            try:
                # Use RLS to ensure user can only edit their own message
                update_ts = datetime.utcnow().isoformat() + "+00:00"
                result = supabase.table('messages').update({
                    'text': new_text,
                    'updated_at': update_ts
                }).eq('id', message_id).eq('user_id', user_id).execute()

                if result.data:
                    socketio_instance.emit('message_edited', {'message_id': message_id, 'text': new_text}, to=room)

            except Exception as e:
                current_app.logger.error(f"Error editing message: {e}")

    @socketio_instance.on('typing')
    def on_typing(data):
        user_id = session.get('user_id')
        if not user_id: return

        room = f"community_{data.get('community_id')}"
        socketio_instance.emit('user_typing', {'username': data.get('username')}, to=room, include_self=False)

    @socketio_instance.on('stop_typing')
    def on_stop_typing(data):
        user_id = session.get('user_id')
        if not user_id: return
        room = f"community_{data.get('community_id')}"
        socketio_instance.emit('user_stopped_typing', {'username': data.get('username')}, to=room, include_self=False)

    @socketio_instance.on('create_poll')
    def on_create_poll(data):
        user_id = session.get('user_id')
        if not user_id: return

        community_id = data.get('community_id')
        question = data.get('question', '').strip()
        options = data.get('options', [])
        room = f'community_{community_id}'

        if not question or len(options) < 2:
            # Optionally, emit an error back to the user
            return

        with current_app.app_context():
            try:
                # Insert poll and get its ID
                poll_resp = supabase.table('polls').insert({
                    'community_id': community_id,
                    'user_id': user_id,
                    'question': question
                }).execute()
                poll = poll_resp.data[0]
                poll_id = poll['id']

                # Prepare and insert options
                options_to_insert = [{'poll_id': poll_id, 'option_text': opt} for opt in options if opt]
                options_resp = supabase.table('poll_options').insert(options_to_insert).execute()
                inserted_options = options_resp.data

                user_resp = supabase.table('users').select('username').eq('id', user_id).single().execute()
                user = user_resp.data

            except Exception as e:
                current_app.logger.error(f"Error creating poll: {e}")
                return

            # Broadcast the new poll to the room
            socketio_instance.emit('new_poll', {
                'poll_id': poll_id,
                'user_id': user_id,
                'question': question,
                'options': [{'id': opt['id'], 'text': opt['option_text'], 'votes': 0} for opt in inserted_options],
                'creator_name': user['username'] if user else 'A user'
            }, to=room)

    @socketio_instance.on('submit_vote')
    def on_submit_vote(data):
        user_id = session.get('user_id')
        if not user_id: return

        poll_id = data.get('poll_id')
        option_id = data.get('option_id')
        community_id = data.get('community_id')
        room = f'community_{community_id}'

        with current_app.app_context():
            try:
                # Upsert allows changing votes. The primary key on (poll_id, user_id) handles this.
                supabase.table('poll_votes').upsert({
                    'poll_id': poll_id,
                    'option_id': option_id,
                    'user_id': user_id
                }).execute()

                # After a successful vote, fetch the entire updated poll state
                # We can use an RPC function for this to be efficient
                poll_update_resp = supabase.rpc('get_poll_results', {'p_poll_id': poll_id}).execute()
                updated_options = poll_update_resp.data or []

                # Broadcast the full update
                socketio_instance.emit('poll_update', {
                    'poll_id': poll_id,
                    'options': updated_options,
                    'voted_option_id': option_id
                }, to=room)

            except Exception as e:
                current_app.logger.error(f"Error submitting vote: {e}")
                # Optionally emit an error to the user
                emit('vote_error', {'poll_id': poll_id, 'message': 'Could not cast vote.'})



    @socketio_instance.on('delete_poll')
    def on_delete_poll(data):
        user_id = session.get('user_id')
        if not user_id: return

        poll_id = data.get('poll_id')
        community_id = data.get('community_id')
        room = f'community_{community_id}'

        with current_app.app_context():
            try:
                # Check if the user is the creator of the poll or an admin
                poll_resp = supabase.table('polls').select('user_id').eq('id', poll_id).single().execute()
                poll = poll_resp.data
                membership_resp = supabase.table('memberships').select('is_admin').match({'user_id': user_id, 'community_id': community_id}).single().execute()
                membership = membership_resp.data

                is_creator = poll and str(poll['user_id']) == str(user_id)
                is_admin = membership and membership['is_admin']

                if is_creator or is_admin:
                    # RLS and CASCADE should handle permissions and cleanup
                    supabase.table('polls').delete().eq('id', poll_id).execute()
                    socketio_instance.emit('poll_deleted', {'poll_id': poll_id}, to=room)
            except Exception as e:
                current_app.logger.error(f"Error deleting poll: {e}")

    @socketio_instance.on('delete_message')
    def on_delete_message(data):
        user_id = session.get('user_id')
        if not user_id: return

        message_id = data.get('message_id')
        community_id = data.get('community_id')
        room = f'community_{community_id}'

        with current_app.app_context():
            try:
                # Let RLS policy on the 'messages' table handle the permission check.
                # The policy should only allow a user to delete their own messages.
                result = supabase.table('messages').delete().eq('id', message_id).eq('user_id', user_id).execute()
                
                # Check if a row was actually deleted
                if result.data:
                    socketio_instance.emit('message_deleted', {'message_id': message_id}, to=room)
            except Exception as e:
                current_app.logger.error(f"Error deleting message: {e}")

    @socketio_instance.on('disconnect')
    def on_disconnect():
        sid = flask_request.sid
        client = clients.pop(sid, None)
        if client:
            community_id = client.get('community_id')
            room = f'community_{community_id}'
            leave_room(room)
            # Broadcast updated member list
