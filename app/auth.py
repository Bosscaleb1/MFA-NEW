from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models import User
import json
import importlib
import ipaddress
import pyotp
import qrcode
from io import BytesIO
import base64

try:
    webauthn_module = importlib.import_module('webauthn')
    webauthn_structs = importlib.import_module('webauthn.helpers.structs')

    generate_registration_options = webauthn_module.generate_registration_options
    verify_registration_response = webauthn_module.verify_registration_response
    generate_authentication_options = webauthn_module.generate_authentication_options
    verify_authentication_response = webauthn_module.verify_authentication_response
    options_to_json = webauthn_module.options_to_json

    AuthenticatorSelectionCriteria = webauthn_structs.AuthenticatorSelectionCriteria
    ResidentKeyRequirement = webauthn_structs.ResidentKeyRequirement
    UserVerificationRequirement = webauthn_structs.UserVerificationRequirement
    PublicKeyCredentialDescriptor = webauthn_structs.PublicKeyCredentialDescriptor

    WEBAUTHN_AVAILABLE = True
    WEBAUTHN_IMPORT_ERROR = None
except Exception as import_error:
    WEBAUTHN_AVAILABLE = False
    WEBAUTHN_IMPORT_ERROR = str(import_error)

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


def _bytes_to_base64url(value):
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode('ascii')


def _base64url_to_bytes(value):
    if not value:
        return b''
    if isinstance(value, bytes):
        return value
    padding = '=' * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode('ascii'))


def _get_webauthn_origin():
    return f"{request.scheme}://{request.host}"


def _get_webauthn_rp_id():
    return request.host.split(':', 1)[0]


def _get_passkey_environment_error():
    host = request.host.split(':', 1)[0].lower()

    try:
        ipaddress.ip_address(host)
        return 'Passkeys are not supported on IP-address hosts. Open this app with http://localhost:5000 for local testing.'
    except ValueError:
        pass

    if request.scheme != 'https' and host != 'localhost':
        return 'Passkeys require HTTPS unless you are using localhost.'

    return None


def _passkey_unavailable_response():
    message = 'Passkeys are unavailable because the webauthn dependency is not installed.'
    if WEBAUTHN_IMPORT_ERROR:
        message = f'{message} ({WEBAUTHN_IMPORT_ERROR})'
    return jsonify({'success': False, 'message': message}), 503

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
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)
        print("[DEBUG-QR] QR code made")
        
        img = qr.make_image(fill_color="black", back_color="white")
        print(f"[DEBUG-QR] Image created, type: {type(img)}")
        
        buffered = BytesIO()
        try:
            img.save(buffered, format="PNG")
            print("[DEBUG-QR] Image saved with format='PNG'")
        except TypeError as e:
            print(f"[DEBUG-QR] TypeError: {e}, trying without format")
            buffered = BytesIO()
            img.save(buffered)
            print("[DEBUG-QR] Image saved without format")
        
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


@auth_bp.route('/passkey/auth/options', methods=['POST'])
def passkey_auth_options():
    if not WEBAUTHN_AVAILABLE:
        return _passkey_unavailable_response()

    environment_error = _get_passkey_environment_error()
    if environment_error:
        return jsonify({'success': False, 'message': environment_error}), 400

    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()

    if not username:
        return jsonify({'success': False, 'message': 'Username is required for passkey sign in'}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not user.has_passkey():
        return jsonify({'success': False, 'message': 'No passkey is registered for this username'}), 404

    try:
        options = generate_authentication_options(
            rp_id=_get_webauthn_rp_id(),
            allow_credentials=[
                PublicKeyCredentialDescriptor(id=_base64url_to_bytes(user.passkey_credential_id)),
            ],
            user_verification=UserVerificationRequirement.PREFERRED,
        )
    except Exception as exc:
        return jsonify({'success': False, 'message': f'Unable to generate passkey auth challenge: {exc}'}), 400

    options_json = json.loads(options_to_json(options))
    session['passkey_auth_challenge'] = options_json['challenge']
    session['passkey_auth_user_id'] = user.id

    return jsonify({'success': True, 'options': options_json}), 200


@auth_bp.route('/passkey/auth/verify', methods=['POST'])
def passkey_auth_verify():
    if not WEBAUTHN_AVAILABLE:
        return _passkey_unavailable_response()

    data = request.get_json(silent=True) or {}
    credential_payload = data.get('credential')
    expected_challenge = session.get('passkey_auth_challenge')
    user_id = session.get('passkey_auth_user_id')

    if not credential_payload:
        return jsonify({'success': False, 'message': 'Passkey credential payload is required'}), 400

    if not expected_challenge or not user_id:
        return jsonify({'success': False, 'message': 'Passkey authentication session expired. Try again.'}), 400

    user = User.query.get(user_id)
    if not user or not user.has_passkey():
        return jsonify({'success': False, 'message': 'User passkey is not configured'}), 400

    try:
        verification = verify_authentication_response(
            credential=credential_payload,
            expected_challenge=_base64url_to_bytes(expected_challenge),
            expected_rp_id=_get_webauthn_rp_id(),
            expected_origin=_get_webauthn_origin(),
            credential_public_key=_base64url_to_bytes(user.passkey_public_key),
            credential_current_sign_count=user.passkey_sign_count or 0,
            require_user_verification=False,
        )
    except Exception as exc:
        return jsonify({'success': False, 'message': f'Passkey verification failed: {exc}'}), 401

    user.passkey_sign_count = verification.new_sign_count
    db.session.commit()

    login_user(user)
    session.pop('passkey_auth_challenge', None)
    session.pop('passkey_auth_user_id', None)

    return jsonify({'success': True, 'message': 'Logged in with passkey'}), 200


@auth_bp.route('/passkey/register/options', methods=['POST'])
@login_required
def passkey_register_options():
    if not WEBAUTHN_AVAILABLE:
        return _passkey_unavailable_response()

    environment_error = _get_passkey_environment_error()
    if environment_error:
        return jsonify({'success': False, 'message': environment_error}), 400

    exclude_credentials = []
    if current_user.passkey_credential_id:
        exclude_credentials.append(
            PublicKeyCredentialDescriptor(id=_base64url_to_bytes(current_user.passkey_credential_id))
        )

    try:
        options = generate_registration_options(
            rp_id=_get_webauthn_rp_id(),
            rp_name='MFA Auth System',
            user_id=str(current_user.id).encode('utf-8'),
            user_name=current_user.username,
            user_display_name=current_user.email,
            exclude_credentials=exclude_credentials,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.PREFERRED,
            ),
        )
    except Exception as exc:
        return jsonify({'success': False, 'message': f'Unable to generate passkey registration challenge: {exc}'}), 400

    options_json = json.loads(options_to_json(options))
    session['passkey_registration_challenge'] = options_json['challenge']

    return jsonify({'success': True, 'options': options_json}), 200


@auth_bp.route('/passkey/register/verify', methods=['POST'])
@login_required
def passkey_register_verify():
    if not WEBAUTHN_AVAILABLE:
        return _passkey_unavailable_response()

    data = request.get_json(silent=True) or {}
    credential_payload = data.get('credential')
    expected_challenge = session.get('passkey_registration_challenge')

    if not credential_payload:
        return jsonify({'success': False, 'message': 'Passkey credential payload is required'}), 400

    if not expected_challenge:
        return jsonify({'success': False, 'message': 'Passkey registration session expired. Try again.'}), 400

    try:
        verification = verify_registration_response(
            credential=credential_payload,
            expected_challenge=_base64url_to_bytes(expected_challenge),
            expected_rp_id=_get_webauthn_rp_id(),
            expected_origin=_get_webauthn_origin(),
            require_user_verification=False,
        )
    except Exception as exc:
        return jsonify({'success': False, 'message': f'Passkey registration failed: {exc}'}), 400

    current_user.passkey_enabled = True
    current_user.passkey_credential_id = _bytes_to_base64url(verification.credential_id)
    current_user.passkey_public_key = _bytes_to_base64url(verification.credential_public_key)
    current_user.passkey_sign_count = verification.sign_count
    db.session.commit()

    session.pop('passkey_registration_challenge', None)
    return jsonify({'success': True, 'message': 'Passkey enabled for your account'}), 200

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
            
            # Generate QR code
            uri = current_user.get_totp_uri()
            print(f"[DEBUG] QR URI: {uri}")
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(uri)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            print(f"[DEBUG] QR image created, type: {type(img)}")
            buffered = BytesIO()
            # Some qrcode image classes (PyPNGImage) do not accept the `format` kwarg.
            # Try the common PIL-style save first, fall back to plain save when needed.
            try:
                img.save(buffered, format="PNG")
                print("[DEBUG] Saved with format='PNG'")
            except TypeError as e:
                print(f"[DEBUG] TypeError with format kwarg, falling back: {e}")
                img.save(buffered)
                print("[DEBUG] Saved without format kwarg")
            
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
    session.pop('passkey_auth_challenge', None)
    session.pop('passkey_auth_user_id', None)
    session.pop('passkey_registration_challenge', None)
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


@auth_bp.route('/disable-passkey', methods=['POST'])
@login_required
def disable_passkey():
    current_user.clear_passkey()
    db.session.commit()
    return jsonify({'success': True, 'message': 'Passkey disabled'}), 200
