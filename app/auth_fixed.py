from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models import User
import pyotp
import qrcode
from io import BytesIO
import base64
from PIL import Image

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/debug-qr')
def debug_qr():
    """Simple endpoint to test QR code generation without login"""
    try:
        print("[DEBUG-QR] Starting QR code generation test")
        
        # Create a simple TOTP instance
        secret = pyotp.random_base32()
        print(f"[DEBUG-QR] Generated secret: {secret}")
        
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name='test@example.com', issuer_name='MFA Test')
        print(f"[DEBUG-QR] Generated URI: {uri}")
        
        # Generate QR code using PIL directly for reliability
        qr = qrcode.QRCode(version=1, box_size=10, border=5, image_factory=qrcode.image.pil.PilImage)
        qr.add_data(uri)
        qr.make(fit=True)
        print("[DEBUG-QR] QR code made")
        
        img = qr.make_image(fill_color="black", back_color="white")
        print(f"[DEBUG-QR] Image created, type: {type(img)}")
        
        # Save to BytesIO with PIL
        buffered = BytesIO()
        img.save(buffered, 'PNG')
        buffered.seek(0)
        img_bytes = buffered.getvalue()
        print(f"[DEBUG-QR] Image bytes: {len(img_bytes)} bytes")
        
        img_str = base64.b64encode(img_bytes).decode()
        print(f"[DEBUG-QR] Base64 encoded: {len(img_str)} chars")
        
        data_uri = f'data:image/png;base64,{img_str}'
        print(f"[DEBUG-QR] Data URI length: {len(data_uri)}")
        
        return jsonify({
            'success': True,
            'secret': secret,
            'qr_code': data_uri,
            'bytes_length': len(img_bytes),
            'base64_length': len(img_str),
            'uri_length': len(data_uri)
        }), 200
    except Exception as e:
        print(f"[DEBUG-QR] ERROR: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@auth_bp.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('auth.dashboard'))
    return redirect(url_for('auth.login'))

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        confirm_password = data.get('confirm_password')
        
        # Validation
        if not all([username, email, password, confirm_password]):
            return jsonify({'success': False, 'message': 'All fields are required'}), 400
        
        if password != confirm_password:
            return jsonify({'success': False, 'message': 'Passwords do not match'}), 400
        
        if len(password) < 6:
            return jsonify({'success': False, 'message': 'Password must be at least 6 characters'}), 400
        
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'message': 'Username already exists'}), 400
        
        if User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'message': 'Email already exists'}), 400
        
        # Create user
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Registration successful. Please log in.'}), 201
    
    return render_template('register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.mfa_enabled:
            return redirect(url_for('auth.verify_mfa'))
        return redirect(url_for('auth.dashboard'))
    
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            if user.mfa_enabled:
                session['user_id'] = user.id
                return jsonify({'success': True, 'requires_mfa': True}), 200
            else:
                login_user(user)
                return jsonify({'success': True, 'requires_mfa': False}), 200
        
        return jsonify({'success': False, 'message': 'Invalid username or password'}), 401
    
    return render_template('login.html')

@auth_bp.route('/setup-mfa', methods=['GET', 'POST'])
@login_required
def setup_mfa():
    if request.method == 'POST':
        data = request.get_json()
        action = data.get('action')
        
        print(f"[DEBUG] setup_mfa POST received, action={action}")
        
        if action == 'generate':
            print(f"[DEBUG] Generate action triggered for user {current_user.username}")
            # Generate new TOTP secret
            current_user.setup_totp()
            db.session.commit()
            print(f"[DEBUG] TOTP secret generated: {current_user.totp_secret[:4]}****")
            
            try:
                # Generate QR code using PIL image factory for reliability
                uri = current_user.get_totp_uri()
                print(f"[DEBUG] QR URI: {uri}")
                qr = qrcode.QRCode(version=1, box_size=10, border=5, image_factory=qrcode.image.pil.PilImage)
                qr.add_data(uri)
                qr.make(fit=True)
                
                img = qr.make_image(fill_color="black", back_color="white")
                print(f"[DEBUG] QR image created, type: {type(img)}")
                
                # Save to BytesIO
                buffered = BytesIO()
                img.save(buffered, 'PNG')
                buffered.seek(0)
                img_bytes = buffered.getvalue()
                print(f"[DEBUG] Image bytes length: {len(img_bytes)}")
                
                if len(img_bytes) == 0:
                    print("[DEBUG] ERROR: Image bytes are empty!")
                    return jsonify({'success': False, 'message': 'Failed to generate QR code image'}), 500
                
                img_str = base64.b64encode(img_bytes).decode()
                print(f"[DEBUG] Base64 encoded length: {len(img_str)}")
                
                qr_code_data_uri = f'data:image/png;base64,{img_str}'
                print(f"[DEBUG] Data URI starts with: {qr_code_data_uri[:50]}...")
                
                response = {
                    'success': True,
                    'secret': current_user.totp_secret,
                    'qr_code': qr_code_data_uri,
                    'uri': uri
                }
                print(f"[DEBUG] Returning response with qr_code length: {len(response['qr_code'])}")
                return jsonify(response), 200
            except Exception as e:
                print(f"[DEBUG] ERROR in QR generation: {e}")
                import traceback
                traceback.print_exc()
                return jsonify({'success': False, 'message': f'Error generating QR code: {str(e)}'}), 500
        
        elif action == 'verify':
            token = data.get('token')
            
            if not current_user.totp_secret:
                return jsonify({'success': False, 'message': 'No secret configured'}), 400
            
            if current_user.verify_totp(token):
                # Generate backup codes
                backup_codes = current_user.generate_backup_codes()
                current_user.mfa_enabled = True
                db.session.commit()
                
                return jsonify({
                    'success': True,
                    'message': 'MFA enabled successfully',
                    'backup_codes': backup_codes
                }), 200
            else:
                return jsonify({'success': False, 'message': 'Invalid token'}), 401
    
    return render_template('setup_mfa.html')

@auth_bp.route('/verify-mfa', methods=['GET', 'POST'])
def verify_mfa():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        data = request.get_json()
        token = data.get('token')
        use_backup = data.get('use_backup', False)
        
        user = User.query.get(session['user_id'])
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 401
        
        if use_backup:
            if user.verify_backup_code(token):
                db.session.commit()
                login_user(user)
                session.pop('user_id', None)
                return jsonify({'success': True, 'message': 'Logged in successfully'}), 200
            else:
                return jsonify({'success': False, 'message': 'Invalid backup code'}), 401
        else:
            if user.verify_totp(token):
                login_user(user)
                session.pop('user_id', None)
                return jsonify({'success': True, 'message': 'Logged in successfully'}), 200
            else:
                return jsonify({'success': False, 'message': 'Invalid token'}), 401
    
    return render_template('verify_mfa.html')

@auth_bp.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'success': True}), 200

@auth_bp.route('/disable-mfa', methods=['POST'])
@login_required
def disable_mfa():
    current_user.mfa_enabled = False
    current_user.totp_secret = None
    current_user.backup_codes = None
    db.session.commit()
    return jsonify({'success': True, 'message': 'MFA disabled'}), 200
