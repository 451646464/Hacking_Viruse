import os
import json
import logging
import re
import tempfile
from flask import session
import random
from fpdf import FPDF
import string
import plotly.graph_objects as go
from io import BytesIO
import smtplib
from email.mime.text import MIMEText
from urllib.parse import urlencode, urlparse, parse_qs, urljoin
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.consumer import oauth_authorized, oauth_error
from flask_dance.consumer.storage.sqla import SQLAlchemyStorage
from sqlalchemy.orm.exc import NoResultFound
import joblib
import requests
from datetime import datetime, timedelta, timezone
from logging.handlers import RotatingFileHandler
from flask import (
    Flask, render_template, request, redirect, url_for,
    send_file, flash, jsonify, abort
)
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user
)
from sandbox import Sandbox
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config
from database import db, init_db
from models import User, AnalysisSample, WebAnalysis, OAuth, CodeAnalysis, ImageAnalysis, UserSettings, Notification
from utils import (
    allowed_file_exe, calculate_file_hash, extract_pe_features,
    predict_sample, generate_pdf_report, create_share_link, safe_delete, extract_strings, run_binwalk, analyze_entropy,
    analyze_network_indicators, apply_yara_rules, extract_libraries, extract_powershell_commands,
    analyze_persistence_mechanisms, detect_c2_servers, detect_packing, mitre_attck_mapping
)
import sys
import io
import secrets
import hashlib

from web_analysis import analyze_url_web, extract_links, SEVERITY_LEVELS
from notification_routes import notifications_bp
from notifications import get_user_notifications, count_unread_notifications
from win_image_analyzer import ImageAnalyzer  # استيراد محلل الصور الجديد

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
# تهيئة التطبيق
app = Flask(__name__)
app.config.from_object(Config)
app.config['SESSION_COOKIE_SECURE'] = False  # أضف هذا السطر
app.config['SESSION_COOKIE_DOMAIN'] = None   #
# في أعلى app.py بعد الاستيرادات
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect(app)

# تعطيل حماية CSRF لمسارات API
csrf.exempt("notification_routes.create_new_notification")
csrf.exempt("notification_routes.mark_read")
csrf.exempt("notification_routes.mark_all_notifications_read")
csrf.exempt("notification_routes.delete_single_notification")
csrf.exempt("notification_routes.delete_admin_notification")

# إضافة فلتر تاريخ مخصص لقوالب Jinja
@app.template_filter('datetime')
def format_datetime(value, format='%Y-%m-%d %H:%M:%S'):
    """تنسيق التاريخ والوقت لقوالب Jinja"""
    if isinstance(value, str):
        try:
            value = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            # محاولة صيغة أخرى إذا فشلت الأولى
            try:
                value = datetime.fromisoformat(value.replace('Z', '+00:00'))
            except ValueError:
                return value
    return value.strftime(format) if value else ''

# أو إذا كنت تستخدم Flask-WTF بالفعل، تأكد من تفعيل حماية CSRF
init_db(app)
# تهيئة نظام تسجيل الدخول
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
# أضف هذه الاستيرادات في الأعلى

# إعدادات جوجل OAuth
app.config['GOOGLE_OAUTH_CLIENT_ID'] ='93378653900-i9lo6160pfs0e2qmuik622tj7odvvh2h.apps.googleusercontent.com'
app.config['GOOGLE_OAUTH_CLIENT_SECRET'] = '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'
# إعدادات إضافية
app.config['ML_MODEL_PATH'] = 'models/image_malware_model.h5'  # مسار نموذج تعلم الآلة

# إنشاء مجلد النماذج إذا لم يكن موجوداً
os.makedirs('models', exist_ok=True)
# إنشاء blueprint للتسجيل عبر جوجل
google_bp = make_google_blueprint(
    scope=["profile", "email"],
    storage=SQLAlchemyStorage(OAuth, db.session, user=current_user),
    redirect_to='dashboard'
)

app.register_blueprint(google_bp, url_prefix="/login")
# تسجيل blueprint الإشعارات
app.register_blueprint(notifications_bp, url_prefix="")
# بعد تعريف load_ml_models()
# إعدادات البريد الإلكتروني
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'rakanalmoliki33@gmail.com'
app.config['MAIL_PASSWORD'] = 'pqiz ooxk jfpa huvo'
app.config['MAIL_DEFAULT_SENDER'] = 'rakanalmoliki33@gmail.com'
app.config['MAIL_USE_SSL'] = False  # أضف هذا السطر
app.config['MAIL_DEBUG'] = True

@oauth_authorized.connect_via(google_bp)
def google_logged_in(blueprint, token):
    if not token:
        flash("Failed to log in with Google.", category="error")
        return False

    resp = blueprint.session.get("/oauth2/v2/userinfo")
    if not resp.ok:
        flash("Failed to fetch user info from Google.", category="error")
        return False

    google_info = resp.json()
    google_user_id = google_info["id"]

    # البحث عن OAuth في قاعدة البيانات
    query = OAuth.query.filter_by(
        provider=blueprint.name,
        provider_user_id=google_user_id
    )
    try:
        oauth = query.one()
    except NoResultFound:
        oauth = OAuth(
            provider=blueprint.name,
            provider_user_id=google_user_id,
            token=token,
        )

    if oauth.user:
        login_user(oauth.user)
        flash("Successfully signed in with Google.")
    else:
        # إنشاء مستخدم جديد
        user = User(
            username=google_info["email"].split("@")[0],
            email=google_info["email"],
            is_verified=True
        )
        oauth.user = user
        db.session.add_all([user, oauth])
        db.session.commit()
        login_user(user)
        flash("Successfully signed up with Google.")

    return False

# معالج لأخطاء OAuth
@oauth_error.connect_via(google_bp)
def google_error(blueprint, error, error_description=None, error_uri=None):
    msg = (
        f"OAuth error from {blueprint.name}! "
        f"error={error} description={error_description} uri={error_uri}"
    )
    flash(msg, category="error")
# توليد كابتشا
def generate_captcha():
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    session['captcha'] = captcha_text
    return captcha_text


# إرسال البريد الإلكتروني
def send_verification_email(email, token):
    try:
        verification_link = url_for('verify_email', token=token, _external=True)
        subject = "تأكيد حسابك في نظام تحليل البرمجيات"
        body = f"مرحباً،\n\nالرجاء الضغط على الرابط التالي لتأكيد حسابك:\n{verification_link}"

        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = app.config['MAIL_DEFAULT_SENDER']
        msg['To'] = email

        with smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT']) as server:
            server.starttls()
            server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
            server.send_message(msg)
        return True
    except Exception as e:
        app.logger.error(f"خطأ في إرسال البريد: {str(e)}")
        return False


# تحديث مسار التسجيل
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        captcha_input = request.form.get('captcha')
        captcha_session = session.get('captcha', '')

        # التحقق من الكابتشا
        if captcha_input != captcha_session:
            flash('Invalid CAPTCHA code', 'error')
            return render_template('signup.html', captcha=generate_captcha())

        # التحقق من كلمة المرور
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('signup.html', captcha=generate_captcha())

        # التحقق من وجود المستخدم
        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()

        if existing_user:
            flash('Username or email already exists', 'error')
            return render_template('signup.html', captcha=generate_captcha())

        # إنشاء المستخدم
        hashed_password = generate_password_hash(password)
        token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))

        new_user = User(
            username=username,
            email=email,
            password=hashed_password,
            verification_token=token
        )

        try:
            db.session.add(new_user)
            db.session.commit()

            # إرسال بريد التفعيل
            if send_verification_email(email, token):
                flash('Account created successfully! Please check your email to verify your account.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Error sending verification email. Please try again later.', 'error')
                return render_template('signup.html', captcha=generate_captcha())

        except Exception as e:
            db.session.rollback()
            flash(f'Error creating account: {str(e)}', 'error')
            app.logger.error(f"Error creating account: {str(e)}")

    return render_template('signup.html', captcha=generate_captcha())

@app.route('/verify/<token>')
def verify_email(token):
    user = User.query.filter_by(verification_token=token).first()
    if user:
        user.is_verified = True
        user.verification_token = None
        db.session.commit()
        flash('تم تفعيل حسابك بنجاح! يمكنك تسجيل الدخول الآن', 'success')
    else:
        flash('رابط التفعيل غير صالح أو منتهي الصلاحية', 'error')
    return redirect(url_for('login'))


# تحديث مسار الدخول
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            if not user.is_verified:
                flash('Your account is not verified. Please check your email.', 'error')
                return redirect(url_for('login'))

            login_user(user)
            user.update_last_login()
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html')




# —————— هنا أضف فلتر hex المخصص ——————
@app.template_filter('hex')
def hex_filter(value):
    try:
        return hex(int(value))
    except (ValueError, TypeError):
        return '0x0'
@app.template_filter('yesno')
def yesno_filter(value, true_label='نعم', false_label='لا'):
    """
    يحول القيم المنطقية إلى نص عربي:
    True  → 'نعم'
    False → 'لا'
    أي قيمة أخرى → ''
    """
    if value is True:
        return true_label
    if value is False:
        return false_label
    return ''
# تهيئة نظام تسجيل الأخطاء
log_formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')

# ملف السجلات
file_handler = RotatingFileHandler('malware_analysis.log', maxBytes=1024 * 1024 * 10, backupCount=5)
file_handler.setFormatter(log_formatter)
file_handler.setLevel(logging.DEBUG)

# وحدة التحكم
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(log_formatter)
stream_handler.setLevel(logging.DEBUG)

app.logger.addHandler(file_handler)
app.logger.addHandler(stream_handler)
app.logger.setLevel(logging.DEBUG)

# تهيئة قاعدة البيانات



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# معالج السياق لتوفير المتغير 'now' لجميع القوالب
@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}


############################################[ image analysis ]##############################################

from datetime import datetime, timezone, timedelta
from flask import render_template, request, flash, redirect, url_for, abort, send_file
from flask_login import login_required, current_user
from sqlalchemy import func
from models import User, AnalysisSample, WebAnalysis, URLAnalysis, PDFAnalysis, CodeAnalysis, ImageAnalysis
from image_analyzer import ImageAnalyzer
from steganography_detector import SteganographyDetector
import os
from werkzeug.utils import secure_filename

# استيراد المكونات الجديدة
from advanced_phishing_detector import AdvancedPhishingDetector
from behavioral_analyzer import BehavioralImageAnalyzer
from threat_intelligence import ThreatIntelligenceIntegration
# استيراد المحلل المدرب بدلاً من المحلل الأساسي
from ml_image_analyzer import *
# التكوين
UPLOAD_FOLDER = 'uploads/images'
ALLOWED_EXTENSIONS_IMAGE = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'webp'}

# دوال تحليل الصور المحدثة
def analyze_image_file(file_path, use_virustotal=False):
    """تحليل ملف صورة باستخدام المحلل الجديد"""
    try:
        vt_api_key = '4f6a1d5109c67e49c1b3e32acd3bf5c89fa500f9db8d759d3fadb2e9da67c94e'
        analyzer = ImageAnalyzer(vt_api_key)
        
        return analyzer.comprehensive_analysis(file_path, use_virustotal)
    except Exception as e:
        app.logger.error(f"Error in image analysis: {str(e)}")
        return {
            'is_malicious': False,
            'prediction': 'خطأ في التحليل',
            'probability': 0.0,
            'risk_score': 0,
            'error': str(e)
        }

def download_and_analyze_image(image_url, use_virustotal=False):
    """تحميل وتحليل صورة من الرابط"""
    temp_path = None
    try:
        temp_path = os.path.join(tempfile.gettempdir(), f"img_url_{datetime.now().strftime('%Y%m%d%H%M%S%f')}")
        
        vt_api_key = '4f6a1d5109c67e49c1b3e32acd3bf5c89fa500f9db8d759d3fadb2e9da67c94e'
        analyzer = ImageAnalyzer(vt_api_key)
        
        # تحميل الصورة
        if analyzer.download_image_from_url(image_url, temp_path):
            # تحليل الصورة
            result = analyzer.comprehensive_analysis(temp_path, use_virustotal)
            safe_delete(temp_path)
            return result
        else:
            if temp_path:
                safe_delete(temp_path)
            return {'error': 'فشل في تحميل الصورة من الرابط'}
            
    except Exception as e:
        if temp_path:
            safe_delete(temp_path)
        return {'error': f'خطأ في تحليل صورة الرابط: {str(e)}'}


# ... (بقية الدوال الموجودة)

def download_and_analyze_image(image_url, use_virustotal=False):
    """تحميل وتحليل صورة من الرابط"""
    try:
        temp_path = os.path.join(tempfile.gettempdir(), f"img_url_{datetime.now().strftime('%Y%m%d%H%M%S%f')}")
        
        vt_api_key = '4f6a1d5109c67e49c1b3e32acd3bf5c89fa500f9db8d759d3fadb2e9da67c94e'
        analyzer = ImageAnalyzer(vt_api_key)
        
        # تحميل الصورة
        if analyzer.download_image_from_url(image_url, temp_path):
            # تحليل الصورة
            result = analyzer.comprehensive_analysis(temp_path, use_virustotal)
            safe_delete(temp_path)
            return result
        else:
            safe_delete(temp_path)
            return {'error': 'فشل في تحميل الصورة من الرابط'}
            
    except Exception as e:
        safe_delete(temp_path)
        return {'error': f'خطأ في تحليل صورة الرابط: {str(e)}'}
@app.route('/image_analysis', methods=['GET', 'POST'])
@login_required
def image_analysis():
    if request.method == 'POST':
        try:
            input_type = request.form.get('input_type', 'file')
            use_virustotal = request.form.get('virustotal_check') == 'on'
            
            app.logger.info(f"بدء تحليل صورة - النوع: {input_type}, VirusTotal: {use_virustotal}")
            
            image_data = None
            filename = ""
            analysis_result = {}
            
            if input_type == 'file':
                if 'image' not in request.files:
                    flash('لم يتم اختيار صورة', 'error')
                    return redirect(request.url)
                
                file = request.files['image']
                if file.filename == '':
                    flash('لم يتم اختيار صورة', 'error')
                    return redirect(request.url)
                
                # التحقق من صيغ الصور المسموحة
                allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'tiff'}
                file_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
                if file_ext not in allowed_extensions:
                    flash('صيغة الصورة غير مدعومة', 'error')
                    return redirect(request.url)
                
                filename = secure_filename(file.filename)
                temp_path = os.path.join(tempfile.gettempdir(), f"img_analysis_{datetime.now().strftime('%Y%m%d%H%M%S%f')}_{hashlib.md5(filename.encode()).hexdigest()[:8]}")
                file.save(temp_path)
                image_data = temp_path
                
                app.logger.info(f"جاري تحليل ملف صورة: {filename}")
                analysis_result = analyze_image_file(temp_path, use_virustotal)
                
            else:  # رابط الصورة
                image_url = request.form.get('image_url', '').strip()
                if not image_url:
                    flash('يجب إدخال رابط الصورة', 'error')
                    return redirect(request.url)
                
                # التحقق من صحة الرابط
                parsed_url = urlparse(image_url)
                if not parsed_url.scheme or not parsed_url.netloc:
                    flash('الرابط غير صحيح', 'error')
                    return redirect(request.url)
                
                filename = os.path.basename(parsed_url.path) or "image_from_url.jpg"
                app.logger.info(f"جاري تحليل صورة من الرابط: {image_url}")
                analysis_result = download_and_analyze_image(image_url, use_virustotal)
            
            # التحقق من وجود خطأ في التحليل
            if 'error' in analysis_result:
                if image_data:
                    safe_delete(image_data)
                app.logger.error(f"خطأ في تحليل الصورة: {analysis_result['error']}")
                flash(f'خطأ في التحليل: {analysis_result["error"]}', 'error')
                return redirect(request.url)
            
            # حساب البصمة والحجم
            file_hash = analysis_result.get('file_hash')
            if not file_hash and image_data:
                file_hash = calculate_file_hash(image_data)
            
            if image_data:
                file_size = os.path.getsize(image_data)
            else:
                file_size = analysis_result.get('file_signatures', {}).get('file_size', 0)
            
            # التحقق من التكرار
            if file_hash:
                existing_analysis = ImageAnalysis.query.filter_by(file_hash=file_hash).first()
                if existing_analysis:
                    if image_data:
                        safe_delete(image_data)
                    app.logger.info(f"تم العثور على تحليل سابق للصورة: {existing_analysis.id}")
                    flash('تم تحليل هذه الصورة سابقاً', 'info')
                    return redirect(url_for('image_report', analysis_id=existing_analysis.id))
            
            # حفظ نتائج التحليل
            image_analysis_record = ImageAnalysis(
                filename=filename,
                file_size=file_size,
                file_hash=file_hash or hashlib.sha256(filename.encode()).hexdigest(),
                is_malicious=analysis_result.get('is_malicious', False),
                risk_score=analysis_result.get('risk_score', 0),  # Mantener el valor original como entero
                user_id=current_user.id
            )
            
            # Set all the analysis results using the proper method
            image_analysis_record.set_analysis_results({
                'prediction': analysis_result.get('prediction', 'غير معروف'),
                'probability': analysis_result.get('probability', 0.0),
                'risk_score': analysis_result.get('risk_score', 0),
                'metadata': analysis_result.get('metadata', {}),
                'steganography_detected': analysis_result.get('steganography_detected', False),
                'steganography_indicators': analysis_result.get('steganography_indicators', []),
                'file_signatures': analysis_result.get('file_signatures', {}),
                'suspicious_patterns': analysis_result.get('suspicious_patterns', [])
            })
            
            image_analysis_record.set_threat_indicators(analysis_result.get('threat_indicators', []))
            
            # حفظ نتائج VirusTotal
            if analysis_result.get('virustotal_result'):
                image_analysis_record.set_virustotal_result(analysis_result['virustotal_result'])
                image_analysis_record.virustotal_scan_date = datetime.utcnow()
            
            db.session.add(image_analysis_record)
            db.session.commit()
            
            # تنظيف الملف المؤقت
            if image_data:
                safe_delete(image_data)
            
            app.logger.info(f"تم تحليل الصورة بنجاح - ID: {image_analysis_record.id}")
            flash('تم تحليل الصورة بنجاح!', 'success')
            return redirect(url_for('image_report', analysis_id=image_analysis_record.id))
            
        except Exception as e:
            app.logger.error(f"خطأ غير متوقع في تحليل الصورة: {str(e)}")
            if image_data:
                safe_delete(image_data)
            flash(f'حدث خطأ غير متوقع أثناء تحليل الصورة: {str(e)}', 'error')
            return redirect(request.url)
    
    # عرض التحليلات الحديثة
    try:
        recent_analyses = ImageAnalysis.query.filter_by(user_id=current_user.id).order_by(
            ImageAnalysis.upload_date.desc()
        ).limit(6).all()
    except Exception as e:
        app.logger.error(f"خطأ في جلب التحليلات الحديثة: {str(e)}")
        recent_analyses = []
    
    return render_template('image_analysis.html', recent_analyses=recent_analyses)
import json as json_module
@app.route('/image_report/<int:analysis_id>')
@login_required
def image_report(analysis_id):
    try:
        analysis = ImageAnalysis.query.get_or_404(analysis_id)
        
        if analysis.user_id != current_user.id and not current_user.is_admin:
            flash('غير مصرح لك بالوصول إلى هذا التقرير', 'danger')
            return redirect(url_for('image_analysis'))
        
        # استخراج البيانات من نتائج التحليل
        results = analysis.get_analysis_results()
        metadata = results.get('metadata', {})
        file_signatures = results.get('file_signatures', {})
        
        return render_template(
            'image_report.html',
            analysis=analysis,
            metadata=metadata,
            file_signatures=file_signatures,
            json=json_module
        )
    except Exception as e:
        flash(f'خطأ في تحميل التقرير: {str(e)}', 'error')
        return redirect(url_for('image_analysis'))
        
# في app.py - إضافة دوال جديدة
@app.route('/share_image_analysis/<int:analysis_id>', methods=['POST'])
@login_required
def share_image_analysis(analysis_id):
    """مشاركة تحليل الصورة"""
    try:
        expiry_days = int(request.form.get('expiry_days', 7))
        analysis = ImageAnalysis.query.get_or_404(analysis_id)
        
        if analysis.user_id != current_user.id and not current_user.is_admin:
            return jsonify({'success': False, 'message': 'غير مصرح لك بمشاركة هذا التحليل'})
        
        # إنشاء رمز المشاركة
        token = hashlib.sha256(f"{analysis.id}{datetime.utcnow()}{secrets.token_hex(8)}".encode()).hexdigest()[:32]
        analysis.share_token = token
        analysis.share_expiry = datetime.utcnow() + timedelta(days=expiry_days)
        
        db.session.commit()
        
        share_url = url_for('shared_image_report', token=token, _external=True)
        return jsonify({
            'success': True,
            'share_url': share_url,
            'expiry': analysis.share_expiry.strftime('%Y-%m-%d %H:%M:%S')
        })
        
    except Exception as e:
        app.logger.error(f"Error sharing image analysis: {str(e)}")
        return jsonify({'success': False, 'message': f'حدث خطأ: {str(e)}'})

@app.route('/shared/image/<token>')
def shared_image_report(token):
    """عرض تحليل الصورة المشترك"""
    try:
        analysis = ImageAnalysis.query.filter_by(share_token=token).first_or_404()
        
        if analysis.share_expiry and analysis.share_expiry < datetime.utcnow():
            abort(410)  # Gone - انتهت صلاحية الرابط
        
        # استخراج البيانات من نتائج التحليل
        results = analysis.get_analysis_results()
        metadata = results.get('metadata', {})
        file_signatures = results.get('file_signatures', {})
        
        return render_template(
            'image_report.html',
            analysis=analysis,
            metadata=metadata,
            file_signatures=file_signatures,
            shared=True
        )
    except Exception as e:
        abort(404)
@app.route('/generate_image_pdf/<int:analysis_id>')
@login_required
def generate_image_pdf(analysis_id):
    """توليد تقرير PDF لتحليل الصورة"""
    try:
        # الحصول على التحليل من قاعدة البيانات
        analysis = ImageAnalysis.query.get_or_404(analysis_id)
        
        # التحقق من صلاحيات المستخدم
        if analysis.user_id != current_user.id and not current_user.is_admin:
            flash('غير مصرح لك بالوصول إلى هذا التقرير', 'danger')
            return redirect(url_for('image_analysis'))
        
        # استخراج البيانات من نتائج التحليل
        analysis_results = analysis.get_analysis_results()
        threat_indicators = analysis.get_threat_indicators()
        
        # استخراج البيانات من النتائج
        prediction = analysis_results.get('prediction', 'غير معروف')
        risk_score = analysis_results.get('risk_score', 0)
        
        # إنشاء ملف PDF
        pdf = FPDF()
        pdf.add_page()
        
        # إضافة محتوى التقرير
        pdf.set_font("Arial", 'B', 16)
        pdf.cell(200, 10, "تقرير تحليل الصورة الأمني", ln=True, align='C')
        pdf.ln(10)
        
        # إضافة البيانات الأساسية
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, f"اسم الملف: {analysis.filename}", ln=True)
        pdf.cell(200, 10, f"الحجم: {analysis.file_size} بايت", ln=True)
        pdf.cell(200, 10, f"البصمة: {analysis.file_hash}", ln=True)
        pdf.cell(200, 10, f"النتيجة: {prediction}", ln=True)
        pdf.cell(200, 10, f"درجة الخطورة: {risk_score}%", ln=True)
        pdf.ln(10)
        
        # إضافة مؤشرات التهديد
        if threat_indicators:
            pdf.cell(200, 10, "مؤشرات التهديد المكتشفة:", ln=True)
            for indicator in threat_indicators:
                pdf.multi_cell(0, 10, f"- {indicator}")
        
        # إرجاع ملف PDF
        pdf_output = BytesIO()
        pdf.output(pdf_output)
        pdf_output.seek(0)
        
        return send_file(
            pdf_output,
            download_name=f"تقرير_تحليل_الصورة_{analysis.filename}.pdf",
            as_attachment=True
        )
        
    except Exception as e:
        flash(f'خطأ في توليد ملف PDF: {str(e)}', 'error')
        return redirect(url_for('image_report', analysis_id=analysis_id))
# تحديث دالة الحذف
@app.route('/delete_image_analysis/<int:analysis_id>', methods=['POST'])
@login_required
def delete_image_analysis(analysis_id):
    """حذف تحليل صورة"""
    try:
        analysis = ImageAnalysis.query.get_or_404(analysis_id)
        
        if analysis.user_id != current_user.id and not current_user.is_admin:
            flash('غير مصرح لك بحذف هذا التحليل', 'danger')
            return redirect(url_for('image_analysis'))
        
        db.session.delete(analysis)
        db.session.commit()
        
        flash('تم حذف التحليل بنجاح', 'success')
        return redirect(url_for('image_analysis'))
        
    except Exception as e:
        flash(f'خطأ في حذف التحليل: {str(e)}', 'error')
        return redirect(url_for('image_report', analysis_id=analysis_id))

############################################[ web analysis ]##############################################
@app.route('/web_analysis', methods=['GET', 'POST'])
@login_required
def web_analysis():
    """تحليل شامل لتطبيقات الويب لاكتشاف الثغرات الأمنية"""
    if request.method == 'POST':
        try:
            # استقبال البيانات من النموذج
            scan_type = request.form.get('scan_type', 'single')
            target = request.form.get('target', '').strip()
            max_pages = int(request.form.get('max_pages', 20))

            # التحقق من صحة الرابط المدخل
            if not target:
                flash('يجب إدخال رابط صحيح', 'danger')
                return redirect(url_for('web_analysis'))

            # إضافة البروتوكول إذا لم يكن موجوداً
            if not target.startswith(('http://', 'https://')):
                target = 'http://' + target

            # تحليل الرابط والتأكد من صحته
            parsed = urlparse(target)
            if not parsed.netloc:
                flash('الرابط المدخل غير صحيح', 'danger')
                return redirect(url_for('web_analysis'))

            domain = parsed.netloc
            start_time = datetime.now()

            # تسجيل بدء عملية الفحص
            app.logger.info(f"بدء فحص الرابط: {target} | نوع الفحص: {scan_type}")

            # عملية الفحص حسب النوع
            if scan_type == 'single':
                # فحص رابط واحد
                report = analyze_url_web(target)
                total_links = 1
                vulnerable_links = 1 if report["vulnerabilities"] else 0
                scan_data = {
                    "domain": domain,
                    "scan_type": "رابط واحد",
                    "total_links": total_links,
                    "vulnerable_links": vulnerable_links,
                    "vulnerabilities": report["vulnerabilities"],
                    "stats": {
                        "total": total_links,
                        "vulnerable": vulnerable_links,
                        "safe": total_links - vulnerable_links,
                        "total_tests": report["stats"].get("total_tests", 0)
                    },
                    "target_url": target,
                    "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
            else:
                # فحص كامل النطاق
                links = extract_links(target, max_pages)

                if not links:
                    flash('لم يتم العثور على روابط تحتوي على معلمات للفحص', 'warning')
                    return redirect(url_for('web_analysis'))

                total_links = len(links)
                vulnerable_links = 0
                vulnerabilities = []
                total_tests = 0
                vulnerable_tests = 0
                
                # فحص جميع الروابط المستخرجة
                for i, link in enumerate(links, 1):
                    try:
                        app.logger.info(f"جاري فحص الرابط {i}/{len(links)}: {link}")
                        report = analyze_url(link)

                        if report["vulnerabilities"]:
                            vulnerable_links += 1
                            vulnerabilities.extend(report["vulnerabilities"])

                        total_tests += report["stats"].get("total_tests", 0)
                        vulnerable_tests += report["stats"].get("vulnerable", 0)

                    except Exception as e:
                        app.logger.error(f"خطأ أثناء فحص الرابط {link}: {str(e)}")
                        continue

                scan_data = {
                    "domain": domain,
                    "scan_type": "نطاق كامل",
                    "total_links": total_links,
                    "vulnerable_links": vulnerable_links,
                    "vulnerabilities": vulnerabilities,
                    "stats": {
                        "total": total_links,
                        "vulnerable": vulnerable_links,
                        "safe": total_links - vulnerable_links,
                        "total_tests": total_tests
                    },
                    "target_url": target,
                    "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }

            # حساب مدة الفحص
            duration = datetime.now() - start_time
            scan_data["duration"] = str(duration)

            # حفظ النتائج في قاعدة البيانات
            web_analysis = WebAnalysis(
                domain=domain,
                scan_type=scan_type,
                total_links=scan_data["total_links"],
                vulnerable_links=scan_data["vulnerable_links"],
                user_id=current_user.id,
                scan_date=datetime.now()
            )

            web_analysis.set_vulnerabilities(scan_data["vulnerabilities"])
            db.session.add(web_analysis)
            db.session.commit()

            # عرض النتائج
            flash(f"تم الانتهاء من الفحص بنجاح! الوقت المستغرق: {duration}", 'success')
            return render_template(
                'web_report.html',
                scan_data=scan_data,
                SEVERITY_LEVELS=SEVERITY_LEVELS,
                analysis_id=web_analysis.id
            )

        except Exception as e:
            db.session.rollback()
            error_msg = f'حدث خطأ أثناء فحص الرابط: {str(e)}'
            app.logger.error(error_msg)
            flash(error_msg, 'danger')
            return redirect(url_for('web_analysis'))

    # عرض صفحة الفحص إذا كانت الطريقة GET
    return render_template('web_analysis.html')


@app.route('/web_report/<int:analysis_id>')
@login_required
def web_analysis_report(analysis_id):
    try:
        analysis = WebAnalysis.query.get_or_404(analysis_id)

        if analysis.user_id != current_user.id and not current_user.is_admin:
            flash('غير مصرح لك بالوصول إلى هذا التقرير', 'danger')
            return redirect(url_for('dashboard'))

        # التأكد من وجود القيم وتعيين قيم افتراضية
        total_links = analysis.total_links if analysis.total_links else 0
        vulnerable_links = analysis.vulnerable_links if analysis.vulnerable_links else 0
        safe_links = total_links - vulnerable_links

        # الحصول على الثغرات الأمنية
        vulnerabilities = []
        try:
            vuln_data = analysis.get_vulnerabilities()
            if vuln_data:
                # التأكد من أن كل عنصر هو dictionary
                for v in vuln_data:
                    if isinstance(v, dict):
                        # إذا كان dictionary، تأكد من وجود الحقول المطلوبة
                        if 'type' not in v:
                            v['type'] = 'Unknown'
                        if 'param' not in v:
                            v['param'] = 'N/A'
                        if 'payload' not in v:
                            v['payload'] = ''
                        if 'severity' not in v:
                            v['severity'] = 'medium'
                        if 'detection_signs' not in v:
                            v['detection_signs'] = []
                        vulnerabilities.append(v)
                    elif isinstance(v, str):
                        # إذا كان string، حاول تحويله إلى dictionary
                        try:
                            parsed = json.loads(v)
                            if isinstance(parsed, dict):
                                vulnerabilities.append(parsed)
                            else:
                                # إنشاء dictionary بسيط
                                vulnerabilities.append({
                                    'type': 'Unknown',
                                    'param': 'N/A',
                                    'payload': str(v),
                                    'severity': 'medium',
                                    'detection_signs': []
                                })
                        except:
                            # إذا فشل parsing، أنشئ dictionary بسيط
                            vulnerabilities.append({
                                'type': 'Unknown',
                                'param': 'N/A',
                                'payload': str(v),
                                'severity': 'medium',
                                'detection_signs': []
                            })
        except Exception as e:
            app.logger.error(f"خطأ في معالجة الثغرات: {str(e)}")
            vulnerabilities = []

        # إنشاء هيكل البيانات المتوقع في القالب
        scan_data = {
            "domain": analysis.domain if analysis.domain else "Unknown",
            "scan_type": "نطاق كامل" if analysis.scan_type == "full" else "رابط واحد",
            "total_links": total_links,  # إضافة للتوافق مع القالب القديم
            "vulnerable_links": vulnerable_links,  # إضافة للتوافق مع القالب القديم
            "stats": {
                "total": total_links,
                "vulnerable": vulnerable_links,
                "safe": safe_links,
                "total_tests": total_links if total_links else 0  # إضافة total_tests للتوافق مع القالب
            },
            "vulnerabilities": vulnerabilities,
            "scan_date": analysis.scan_date.strftime("%Y-%m-%d %H:%M:%S") if analysis.scan_date else "N/A"
        }

        return render_template(
            'web_report.html',
            scan_data=scan_data,
            SEVERITY_LEVELS=SEVERITY_LEVELS,
            analysis_id=analysis.id
        )
    except Exception as e:
        app.logger.error(f"خطأ في تحميل التقرير: {str(e)}")
        app.logger.error(f"تفاصيل الخطأ: {type(e).__name__}")
        import traceback
        app.logger.error(traceback.format_exc())
        flash('حدث خطأ أثناء تحميل التقرير: ' + str(e), 'danger')
        return redirect(url_for('dashboard'))

@app.route('/share_web_scan/<scan_id>', methods=['POST'])
def share_web_scan(scan_id):
    # الكود الخاص بمشاركة تقرير الويب
    pass





############################################[ pdf analysis ]##############################################
# إضافة الاستيرادات اللازمة
############################################[ pdf analysis - IMPROVED ]##############################################

import os
import re
import tempfile
import requests
import PyPDF2
import pdfplumber
from pdfminer.high_level import extract_text
from flask import request, flash, redirect, url_for, render_template, jsonify
from flask_login import login_required, current_user
from models import PDFAnalysis
import json
from datetime import datetime, timezone
from werkzeug.utils import secure_filename
import hashlib

# استيراد الدوال المساعدة
from utils import calculate_file_hash, safe_delete

# الحصول على مفاتيح API من متغيرات البيئة
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')
METADEFENDER_API_KEY = os.environ.get('METADEFENDER_API_KEY')


def extract_pdf_metadata(file_path):
    """استخراج metadata من ملف PDF مع تحسينات"""
    metadata = {}
    try:
        with open(file_path, 'rb') as file:
            pdf_reader = PyPDF2.PdfReader(file)
            metadata = dict(pdf_reader.metadata) if pdf_reader.metadata else {}

            # إضافة معلومات إضافية
            metadata['num_pages'] = len(pdf_reader.pages)
            metadata['is_encrypted'] = pdf_reader.is_encrypted

            # فحص الإصدار
            metadata['pdf_version'] = getattr(pdf_reader, 'pdf_header', 'Unknown')

    except Exception as e:
        app.logger.error(f"خطأ في استخراج metadata: {str(e)}")
    return metadata


def extract_pdf_text(file_path):
    """استخراج النص من ملف PDF مع معالجة الأخطاء"""
    try:
        text = extract_text(file_path)
        return text
    except Exception as e:
        app.logger.error(f"خطأ في استخراج النص: {str(e)}")
        return ""


def analyze_pdf_structure(file_path):
    """تحليل هيكل PDF مع فحص متقدم"""
    structure_info = {
        'pages': 0,
        'forms': False,
        'javascript': False,
        'embedded_files': False,
        'actions': False,
        'auto_launch': False,
        'suspicious_objects': []
    }

    try:
        with pdfplumber.open(file_path) as pdf:
            structure_info['pages'] = len(pdf.pages)

            # تحليل كل صفحة
            for page_num, page in enumerate(pdf.pages):
                page_text = str(page) if page else ""

                # فحص JavaScript
                if '/JS' in page_text or '/JavaScript' in page_text:
                    structure_info['javascript'] = True
                    structure_info['suspicious_objects'].append(f"JavaScript في الصفحة {page_num + 1}")

                # فحص الإجراءات
                if '/AA' in page_text or '/OpenAction' in page_text:
                    structure_info['actions'] = True
                    structure_info['auto_launch'] = True
                    structure_info['suspicious_objects'].append(f"إجراء تلقائي في الصفحة {page_num + 1}")

                if page.annots:
                    structure_info['forms'] = True

                if '/EmbeddedFiles' in page_text:
                    structure_info['embedded_files'] = True
                    structure_info['suspicious_objects'].append(f"ملفات مضمنة في الصفحة {page_num + 1}")

        # فحص إضافي باستخدام PyPDF2
        with open(file_path, 'rb') as file:
            pdf_reader = PyPDF2.PdfReader(file)

            # فحص جميع الصفحات بشكل أعمق
            for page_num, page in enumerate(pdf_reader.pages):
                page_text = page.extract_text() if hasattr(page, 'extract_text') else ""

                # فحص الروابط والأنماط الخطيرة
                if '/URI' in str(page) or '/Launch' in str(page):
                    structure_info['suspicious_objects'].append(f"إطلاق تطبيقات خارجية في الصفحة {page_num + 1}")

    except Exception as e:
        app.logger.error(f"خطأ في تحليل الهيكل: {str(e)}")

    return structure_info


def scan_with_virustotal(file_path, api_key):
    """فحص الملف باستخدام VirusTotal API مع معالجة محسنة"""
    try:
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'

        with open(file_path, 'rb') as file:
            files = {'file': (os.path.basename(file_path), file)}
            params = {'apikey': api_key}

            response = requests.post(url, files=files, params=params, timeout=30)

            if response.status_code == 200:
                result = response.json()
                # الحصول على التقرير بعد الفحص
                scan_id = result.get('scan_id')
                if scan_id:
                    report = get_virustotal_report(scan_id, api_key)
                    return report
                return result
            else:
                app.logger.error(f"VirusTotal API error: {response.status_code}")
                return {'error': f'HTTP {response.status_code}', 'detected': False}

    except requests.exceptions.Timeout:
        app.logger.error("VirusTotal request timeout")
        return {'error': 'Request timeout', 'detected': False}
    except Exception as e:
        app.logger.error(f"VirusTotal scan error: {str(e)}")
        return {'error': str(e), 'detected': False}


def get_virustotal_report(scan_id, api_key, max_retries=3):
    """الحصول على تقرير VirusTotal بعد الفحص"""
    for attempt in range(max_retries):
        try:
            import time
            time.sleep(15)  # انتظار 15 ثانية ليكتمل الفحص

            url = 'https://www.virustotal.com/vtapi/v2/file/report'
            params = {'apikey': api_key, 'resource': scan_id}

            response = requests.get(url, params=params, timeout=30)

            if response.status_code == 200:
                result = response.json()
                if result.get('response_code') == 1:  # الفحص مكتمل
                    positives = result.get('positives', 0)
                    total = result.get('total', 0)
                    return {
                        'detected': positives > 0,
                        'positives': positives,
                        'total': total,
                        'scan_date': result.get('scan_date'),
                        'permalink': result.get('permalink'),
                        'scans': result.get('scans', {})
                    }
        except Exception as e:
            app.logger.error(f"Error getting VirusTotal report: {str(e)}")
            continue

    return {'error': 'Failed to get report', 'detected': False}


def scan_with_metadefender(file_path, api_key):
    """فحص الملف باستخدام MetaDefender API مع معالجة محسنة"""
    try:
        url = 'https://api.metadefender.com/v4/file'
        headers = {
            'apikey': api_key,
            'content-type': 'application/octet-stream'
        }

        with open(file_path, 'rb') as file:
            file_data = file.read()
            response = requests.post(url, headers=headers, data=file_data, timeout=60)

            if response.status_code == 200:
                result = response.json()
                data_id = result.get('data_id')

                if data_id:
                    # الانتظار والحصول على النتائج
                    return get_metadefender_results(data_id, api_key)
                return result
            else:
                app.logger.error(f"MetaDefender API error: {response.status_code}")
                return {'error': f'HTTP {response.status_code}', 'detected': False}

    except requests.exceptions.Timeout:
        app.logger.error("MetaDefender request timeout")
        return {'error': 'Request timeout', 'detected': False}
    except Exception as e:
        app.logger.error(f"MetaDefender scan error: {str(e)}")
        return {'error': str(e), 'detected': False}


def get_metadefender_results(data_id, api_key, max_retries=5):
    """الحصول على نتائج MetaDefender"""
    url = f'https://api.metadefender.com/v4/file/{data_id}'
    headers = {'apikey': api_key}

    for attempt in range(max_retries):
        try:
            import time
            time.sleep(10)  # انتظار 10 ثواني بين المحاولات

            response = requests.get(url, headers=headers, timeout=30)

            if response.status_code == 200:
                result = response.json()
                scan_results = result.get('scan_results', {})

                if scan_results.get('scan_all_result_a') != 'In Progress':
                    total_avs = scan_results.get('total_avs', 0)
                    total_detected = scan_results.get('total_detected_avs', 0)

                    return {
                        'detected': total_detected > 0,
                        'total_avs': total_avs,
                        'total_detected': total_detected,
                        'scan_details': scan_results.get('scan_details', {}),
                        'scan_all_result_a': scan_results.get('scan_all_result_a')
                    }
        except Exception as e:
            app.logger.error(f"Error getting MetaDefender results: {str(e)}")
            continue

    return {'error': 'Scan timeout or failed', 'detected': False}


def analyze_pdf_content(text):
    """تحليل محتوى PDF لاكتشاف التهديدات بشكل متقدم"""
    threats = []

    # اكتشاف JavaScript خطير وأنماط تنفيذية
    js_patterns = [
        (r'eval\s*\(', 'دالة eval الخطيرة'),
        (r'exec\s*\(', 'دالة exec التنفيذية'),
        (r'fromCharCode\s*\(', 'تحويل الأحرف المشفرة'),
        (r'document\.write\s*\(', 'كتابة مباشرة في المستند'),
        (r'window\.open\s*\(', 'فتح نوافذ جديدة'),
        (r'window\.location\s*=', 'تغيير عنوان الصفحة'),
        (r'javascript:', 'نص JavaScript مضمن'),
        (r'vbscript:', 'نص VBScript مضمن'),
        (r'msiexec', 'تنفيذ حزم Windows'),
        (r'cmd\.exe', 'تنفيذ أوامر cmd'),
        (r'powershell', 'تنفيذ PowerShell'),
        (r'regsvr32', 'تسجيل مكتبات'),
        (r'rundll32', 'تنفيذ DLLs'),
        (r'ShellExecute', 'تنفيذ أوامر النظام'),
        (r'ActiveXObject', 'كائنات ActiveX'),
        (r'Scripting\.FileSystemObject', 'الوصول إلى نظام الملفات')
    ]

    for pattern, description in js_patterns:
        matches = re.finditer(pattern, text, re.IGNORECASE)
        for match in matches:
            threats.append({
                'type': 'كود تنفيذي',
                'description': f'{description} - "{match.group()}"',
                'severity': 'high',
                'position': f"النص حول: {text[max(0, match.start() - 50):match.end() + 50]}..."
            })

    # اكتشاف روابط مشبوهة
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    matches = re.finditer(url_pattern, text)
    for match in matches:
        url = match.group()
        if is_suspicious_url(url):
            threats.append({
                'type': 'رابط مشبوه',
                'description': f'رابط مشبوه: {url}',
                'severity': 'medium',
                'details': f'تم اكتشاف رابط إلى موقع مشبوه'
            })

    # اكتشاف تعليمات PDF خطيرة
    pdf_instructions = [
        (r'/JS\s', 'كود JavaScript'),
        (r'/JavaScript\s', 'كود JavaScript'),
        (r'/AA\s', 'إجراء تلقائي'),
        (r'/OpenAction\s', 'إجراء عند الفتح'),
        (r'/Launch\s', 'إطلاق تطبيقات'),
        (r'/URI\s', 'روابط خارجية'),
        (r'/SubmitForm\s', 'إرسال بيانات النماذج'),
        (r'/GoToR\s', 'الذهاب إلى ملف خارجي'),
        (r'/RichMedia\s', 'وسائط متعددة')
    ]

    for pattern, description in pdf_instructions:
        if re.search(pattern, text):
            threats.append({
                'type': 'تعليمات PDF خطيرة',
                'description': f'تعليمات {description} في PDF',
                'severity': 'high'
            })

    return threats

def calculate_threat_score(api_results, threats, structure_info=None):
    """حساب درجة التهديد بشكل أكثر دقة"""
    score = 0

    # نقاط بناء على نتائج APIs
    for engine, result in api_results.items():
        if result.get('detected', False):
            score += 30  # نقاط أساسية لاكتشاف أي محرك

    # نقاط بناء على التهديدات المكتشفة
    for threat in threats:
        if threat['severity'] == 'high':
            score += 15
        elif threat['severity'] == 'medium':
            score += 8
        else:
            score += 3

    # نقاط بناء على هيكل PDF إذا كان متوفراً
    if structure_info:
        if structure_info.get('javascript', False):
            score += 20
        if structure_info.get('auto_launch', False):
            score += 15
        if structure_info.get('embedded_files', False):
            score += 10
        if structure_info.get('actions', False):
            score += 10
        # إضافة النقاط من الكائنات المشبوهة
        suspicious_objects = structure_info.get('suspicious_objects', [])
        score += min(len(suspicious_objects) * 5, 20)

    return min(score, 100)
def is_suspicious_url(url):
    """التحقق إذا كان الرابط مشبوهاً"""
    suspicious_domains = [
        'free', 'download', 'virus', 'malware', 'trojan',
        'hack', 'crack', 'keygen', 'torrent', 'warez',
        'nulled', 'cracks', 'serial', 'keygen'
    ]

    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz']

    url_lower = url.lower()

    # فحص النطاقات المشبوهة
    if any(domain in url_lower for domain in suspicious_domains):
        return True

    # فحص نطاقات المستوى الأعلى المشبوهة
    if any(url_lower.endswith(tld) for tld in suspicious_tlds):
        return True

    # فحص عناوين IP مباشرة
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    if re.search(ip_pattern, url):
        return True

    return False


@app.route('/pdf_analysis', methods=['GET', 'POST'])
@login_required
def pdf_analysis():
    if request.method == 'POST':
        if 'pdf_file' not in request.files:
            flash('لم يتم اختيار ملف', 'error')
            return redirect(request.url)

        file = request.files['pdf_file']
        if file.filename == '':
            flash('لم يتم اختيار ملف', 'error')
            return redirect(request.url)

        if not file.filename.lower().endswith('.pdf'):
            flash('صيغة غير مدعومة، اختر ملف PDF', 'error')
            return redirect(request.url)

        # حفظ الملف مؤقتاً
        temp_dir = tempfile.gettempdir()
        temp_filename = f"pdf_analysis_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}.pdf"
        file_path = os.path.join(temp_dir, temp_filename)

        try:
            file.save(file_path)
        except Exception as e:
            flash(f'خطأ في حفظ الملف: {str(e)}', 'error')
            return redirect(request.url)

        # حساب hash وحجم الملف
        try:
            file_size = os.path.getsize(file_path)
            file_hash = calculate_file_hash(file_path)
        except Exception as e:
            safe_delete(file_path)
            flash(f'خطأ في قراءة الملف: {str(e)}', 'error')
            return redirect(request.url)

        filename = secure_filename(file.filename)

        # التحقق من وجود تحليل سابق
        existing_analysis = PDFAnalysis.query.filter_by(file_hash=file_hash).first()
        if existing_analysis:
            safe_delete(file_path)
            flash('تم تحليل هذا الملف سابقاً', 'info')
            return redirect(url_for('pdf_report', analysis_id=existing_analysis.id))

        # تحليل PDF
        try:
            start_time = datetime.now(timezone.utc)

            # استخراج metadata والنص والهيكل
            metadata = extract_pdf_metadata(file_path)
            text_content = extract_pdf_text(file_path)
            structure_info = analyze_pdf_structure(file_path)

            # فحص باستخدام APIs
            selected_engines = request.form.getlist('engines')
            api_results = {}

            if 'virustotal' in selected_engines and VIRUSTOTAL_API_KEY:
                api_results['virustotal'] = scan_with_virustotal(file_path, VIRUSTOTAL_API_KEY)

            if 'metadefender' in selected_engines and METADEFENDER_API_KEY:
                api_results['metadefender'] = scan_with_metadefender(file_path, METADEFENDER_API_KEY)

            # تحليل النص لاكتشاف التهديدات
            threats = analyze_pdf_content(text_content)

            # تحديد إذا كان الملف ضاراً
            is_malicious = any(
                result.get('detected', False) for result in api_results.values()
            ) or len(threats) > 0 or len(structure_info.get('suspicious_objects', [])) > 0

            # حساب درجة التهديد
            threat_score = calculate_threat_score(api_results, threats, structure_info)

            # حساب مدة الفحص
            end_time = datetime.now(timezone.utc)
            scan_duration = end_time - start_time

            # حفظ النتائج في قاعدة البيانات
            pdf_analysis = PDFAnalysis(
                user_id=current_user.id,
                filename=filename,
                file_hash=file_hash,
                file_size=file_size,
                is_malicious=is_malicious,
                threat_score=threat_score,
                engines_used=json.dumps(selected_engines),
                engines_total=len(selected_engines),
                engines_detected=sum(1 for r in api_results.values() if r.get('detected', False)),
                upload_date=datetime.now(timezone.utc),
                scan_date=datetime.now(timezone.utc)
            )

            pdf_analysis.set_results(api_results)
            pdf_analysis.set_vulnerabilities(threats)
            pdf_analysis.set_file_metadata({
                'metadata': metadata,
                'structure': structure_info,
                'text_length': len(text_content),
                'scan_duration': str(scan_duration),
                'suspicious_objects': structure_info.get('suspicious_objects', [])
            })

            db.session.add(pdf_analysis)
            db.session.commit()

            safe_delete(file_path)

            if is_malicious:
                flash('تم اكتشاف تهديدات في الملف!', 'danger')
            else:
                flash('تم تحليل الملف بنجاح - لم يتم اكتشاف تهديدات', 'success')

            return redirect(url_for('pdf_report', analysis_id=pdf_analysis.id))

        except Exception as e:
            safe_delete(file_path)
            error_msg = f'خطأ في تحليل الملف: {str(e)}'
            app.logger.error(error_msg)
            flash(error_msg, 'error')
            return redirect(request.url)

    return render_template('pdf_analysis.html')


# باقي الكود بدون تغيير...


@app.route('/pdf_report/<int:analysis_id>')
@login_required
def pdf_report(analysis_id):
    try:
        analysis = PDFAnalysis.query.get_or_404(analysis_id)

        if analysis.user_id != current_user.id and not current_user.is_admin:
            flash('غير مصرح لك بالوصول إلى هذا التقرير', 'danger')
            return redirect(url_for('dashboard'))

        # الحصول على البيانات من النموذج - استخدام الدالة الجديدة
        results = analysis.get_results()
        vulnerabilities = analysis.get_vulnerabilities()
        file_metadata = analysis.get_file_metadata()  # تغيير هنا

        # تمرير البيانات للقالب
        return render_template(
            'pdf_report.html',
            analysis=analysis,
            results=results,
            vulnerabilities=vulnerabilities,
            file_metadata=file_metadata  # تغيير هنا أيضاً
        )
    except Exception as e:
        flash(f'خطأ في تحميل التقرير: {str(e)}', 'error')
        return redirect(url_for('pdf_analysis'))


@app.route('/delete_pdf_report/<int:analysis_id>', methods=['DELETE'])
@login_required
def delete_pdf_report(analysis_id):
    try:
        analysis = PDFAnalysis.query.get_or_404(analysis_id)

        # التحقق من صلاحية المستخدم
        if analysis.user_id != current_user.id and not current_user.is_admin:
            return jsonify({
                'success': False,
                'message': 'غير مصرح لك بحذف هذا التقرير'
            }), 403

        # حذف التقرير
        db.session.delete(analysis)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'تم حذف التقرير بنجاح'
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"خطأ في حذف التقرير: {str(e)}")

        return jsonify({
            'success': False,
            'message': f'حدث خطأ أثناء حذف التقرير: {str(e)}'
        }), 500
# وظائف مساعدة









############################################[ URL  analysis ]##############################################



from url_analyzer import analyze_url, setup_selenium  # إضافة هذا
from models import URLAnalysis  # إضافة هذا


# ... (بقية الكود)

@app.route('/URL_analysis', methods=['GET', 'POST'])
@login_required
def url_analysis():
    if request.method == 'POST':
        url = request.form.get('url')
        if not url:
            flash('يجب إدخال رابط صحيح', 'danger')
            return redirect(url_for('url_analysis'))

        try:
            # استبدل بالمفتاح الخاص بك من VirusTotal
            VT_API_KEY = "4f6a1d5109c67e49c1b3e32acd3bf5c89fa500f9db8d759d3fadb2e9da67c94e"

            driver = setup_selenium()
            results = analyze_url(url, driver, vt_api_key=VT_API_KEY)
            driver.quit()

            if 'error' in results:
                flash(results['error'], 'danger')
                return redirect(url_for('url_analysis'))

            # حفظ النتائج في قاعدة البيانات
            url_analysis = URLAnalysis(
                url=url,
                is_malicious="مشبوه" in results['final_result'],
                ssl_status=results['ssl_status'],
                model_prediction=results['model_prediction'],
                content_analysis=results['content_analysis'],
                html_analysis=results['html_analysis'],
                javascript_analysis=results['javascript_analysis'],
                virustotal_result=results['virustotal_result'],
                final_result=results['final_result'],
                user_id=current_user.id
            )

            db.session.add(url_analysis)
            db.session.commit()

            return redirect(url_for('report_url_analysis', analysis_id=url_analysis.id))

        except Exception as e:
            flash(f'حدث خطأ أثناء تحليل الرابط: {str(e)}', 'danger')
            app.logger.error(f"خطأ في تحليل الرابط: {str(e)}")
            
    return render_template('URL_analysis.html')


@app.route('/report_url_analysis/<int:analysis_id>')
@login_required
def report_url_analysis(analysis_id):
    try:
        analysis = URLAnalysis.query.get_or_404(analysis_id)

        if analysis.user_id != current_user.id and not current_user.is_admin:
            flash('غير مصرح لك بالوصول إلى هذا التقرير', 'danger')
            return redirect(url_for('dashboard'))
        
        # إضافة الوقت الحالي للقالب
        import datetime
        current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        return render_template('report_url_analysis.html', 
                               results=analysis.to_dict(),
                               analysis=analysis,  # إضافة متغير analysis للقالب
                               current_time=current_time)  # إضافة الوقت الحالي
    except Exception as e:
        flash(f'خطأ في تحميل التقرير: {str(e)}', 'danger')
        app.logger.error(f"خطأ في تحميل التقرير: {str(e)}")
        return redirect(url_for('url_analysis'))

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'sample' not in request.files:
            flash('لم يتم اختيار ملف', 'error')
            return redirect(request.url)

        file = request.files['sample']

        if file.filename == '':
            flash('لم يتم اختيار ملف', 'error')
            return redirect(request.url)

        if not allowed_file_exe(file.filename):
            flash('صيغة غير مدعومة، اختر ملف exe أو dll', 'error')
            return redirect(request.url)

        # استخدام ملف مؤقت بدلاً من الحفظ المباشر
        temp_dir = tempfile.gettempdir()
        temp_filename = f"malware_analysis_{datetime.now().strftime('%Y%m%d%H%M%S%f')}.bin"
        file_path = os.path.join(temp_dir, temp_filename)

        try:
            file.save(file_path)
        except Exception as e:
            flash(f'خطأ في حفظ الملف: {str(e)}', 'error')
            app.logger.error(f"خطأ في حفظ الملف: {str(e)}")
            return redirect(request.url)

        # حساب حجم الملف فوراً قبل أي عمليات أخرى
        try:
            file_size = os.path.getsize(file_path)
        except Exception as e:
            safe_delete(file_path)
            flash(f'خطأ في قراءة الملف: {str(e)}', 'error')
            app.logger.error(f"خطأ في قراءة الملف: {str(e)}")
            return redirect(request.url)

        filename = secure_filename(file.filename)

        try:
            file_hash = calculate_file_hash(file_path)
        except Exception as e:
            safe_delete(file_path)
            flash(f'خطأ في حساب بصمة الملف: {str(e)}', 'error')
            app.logger.error(f"خطأ في حساب بصمة الملف: {str(e)}")
            return redirect(request.url)

        # التحقق مما إذا كانت العينة محللة سابقاً
        existing_sample = AnalysisSample.query.filter_by(file_hash=file_hash).first()
        if existing_sample:
            safe_delete(file_path)
            flash('تم تحليل هذه العينة سابقاً', 'info')
            return redirect(url_for('sample_detail', sample_id=existing_sample.id))

        # استخراج الميزات
        try:
            header_info, sections_info, imports_info, dynamic_indicators = extract_pe_features(file_path)
        except Exception as e:
            safe_delete(file_path)
            flash(f'خطأ في استخراج ميزات الملف: {str(e)}', 'error')
            app.logger.error(f"خطأ في استخراج ميزات الملف: {str(e)}")
            return redirect(request.url)

        # التصنيف باستخدام نموذج ML
        try:
            pred, proba = predict_sample(file_path)
            is_malicious = pred == 1
        except Exception as e:
            safe_delete(file_path)
            flash(f'خطأ في تحليل الملف: {str(e)}', 'error')
            app.logger.error(f"خطأ في تحليل الملف: {str(e)}")
            return redirect(request.url)

        # التحليلات الجديدة
        strings = extract_strings(file_path)
        binwalk_results = run_binwalk(file_path)
        entropy = analyze_entropy(file_path)
        packed, _ = detect_packing(file_path)
        network_indicators = analyze_network_indicators(strings)
        yara_matches = apply_yara_rules(file_path)
        libraries = extract_libraries(file_path)
        powershell_commands = extract_powershell_commands(strings)
        persistence_indicators = analyze_persistence_mechanisms(strings)
        c2_indicators = detect_c2_servers(
            network_indicators['domains'],
            network_indicators['ips']
        )
        mitre_techniques = mitre_attck_mapping(
            strings +
            [match['rule'] for match in yara_matches] +
            persistence_indicators
        )

        sandbox_report = {}
        if Config.DYNAMIC_ANALYSIS_ENABLED:
            sandbox = Sandbox(file_path)
            sandbox_report = sandbox.run()

        # حذف الملف المؤقت بعد الانتهاء من التحليل
        if not safe_delete(file_path):
            app.logger.warning(f"تعذر حذف الملف المؤقت: {file_path}")

        # إصلاح: تطبيق معالجة خاصة على البيانات قبل التخزين
        libraries = fix_stored_data(libraries)
        powershell_commands = fix_stored_data(powershell_commands)
        persistence_indicators = fix_stored_data(persistence_indicators)
        c2_indicators = fix_stored_data(c2_indicators)

        # حفظ العينة في قاعدة البيانات
        try:
            sample = AnalysisSample(
                filename=filename,
                file_size=file_size,
                file_hash=file_hash,
                prediction='خبيث' if is_malicious else 'آمن',
                probability=proba,
                is_malicious=is_malicious,
                user_id=current_user.id if current_user.is_authenticated else None,
                header_info=json.dumps(header_info),
                sections_info=json.dumps(sections_info),
                imports_info=json.dumps(imports_info),
                dynamic_indicators=json.dumps(dynamic_indicators),
                strings=json.dumps(strings),
                binwalk_results=json.dumps(binwalk_results),
                entropy=entropy,
                packed=packed,
                network_indicators=json.dumps(network_indicators),
                yara_matches=json.dumps([match['rule'] for match in yara_matches]),
                libraries=json.dumps(libraries),
                powershell_commands=json.dumps(powershell_commands),
                persistence_indicators=json.dumps(persistence_indicators),
                c2_indicators=json.dumps(c2_indicators),
                mitre_techniques=json.dumps(mitre_techniques)
            )

            db.session.add(sample)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash(f'خطأ في حفظ نتائج التحليل: {str(e)}', 'error')
            app.logger.error(f"خطأ في حفظ نتائج التحليل: {str(e)}")
            return redirect(request.url)

        return redirect(url_for('sample_detail', sample_id=sample.id))

    return render_template('index.html')


@app.route('/sample/<int:sample_id>')
def sample_detail(sample_id):
    try:
        sample = AnalysisSample.query.get_or_404(sample_id)

        # إصلاح: معالجة البيانات المخزنة قبل العرض
        def fix_data(data):
            if isinstance(data, list):
                if all(isinstance(item, list) for item in data):
                    return [''.join(item) for item in data]
            return data

        # تحويل البيانات من JSON إلى كائنات Python
        header_info = json.loads(sample.header_info) if sample.header_info else {}
        sections_info = json.loads(sample.sections_info) if sample.sections_info else []
        imports_info = json.loads(sample.imports_info) if sample.imports_info else {}
        dynamic_indicators = json.loads(sample.dynamic_indicators) if sample.dynamic_indicators else {}
        strings = json.loads(sample.strings) if sample.strings else {}
        binwalk_results = json.loads(sample.binwalk_results) if sample.binwalk_results else []
        network_indicators = json.loads(sample.network_indicators) if sample.network_indicators else {}
        yara_matches = json.loads(sample.yara_matches) if sample.yara_matches else []
        libraries = json.loads(sample.libraries) if sample.libraries else []
        powershell_commands = json.loads(sample.powershell_commands) if sample.powershell_commands else []
        persistence_indicators = json.loads(sample.persistence_indicators) if sample.persistence_indicators else []
        c2_indicators = json.loads(sample.c2_indicators) if sample.c2_indicators else []
        mitre_techniques = json.loads(sample.mitre_techniques) if sample.mitre_techniques else []

        # إصلاح: معالجة المكتبات والأوامر
        libraries = fix_data(libraries)
        powershell_commands = fix_data(powershell_commands)
        persistence_indicators = fix_data(persistence_indicators)
        c2_indicators = fix_data(c2_indicators)

        # إضافة متغير sandbox_report فارغ لتجنب الأخطاء في القالب
        sandbox_report = {}

        return render_template(
            'report.html',
            sample=sample,
            strings=strings,
            header_info=header_info,
            sections_info=sections_info,
            imports_info=imports_info,
            dynamic_indicators=dynamic_indicators,
            sandbox_report=sandbox_report,
            binwalk_results=binwalk_results,
            entropy=sample.entropy,
            packed=sample.packed,
            network_indicators=network_indicators,
            yara_matches=yara_matches,
            libraries=libraries,
            powershell_commands=powershell_commands,
            persistence_indicators=persistence_indicators,
            c2_indicators=c2_indicators,
            mitre_techniques=mitre_techniques
        )
    except Exception as e:
        flash(f'خطأ في تحميل التقرير: {str(e)}', 'error')
        app.logger.error(f"خطأ في تحميل التقرير: {str(e)}")
        return redirect(url_for('index'))


@app.route('/share/<token>')
def shared_report(token):
    try:
        sample = AnalysisSample.query.filter_by(share_token=token).first()
        if not sample:
            flash('رابط التقرير غير صالح أو منتهي الصلاحية', 'error')
            return redirect(url_for('index'))

        if sample.share_expiry and sample.share_expiry < datetime.utcnow():
            flash('انتهت صلاحية رابط التقرير', 'error')
            return redirect(url_for('index'))

        # إصلاح: معالجة البيانات المخزنة قبل العرض
        def fix_data(data):
            if isinstance(data, list):
                if all(isinstance(item, list) for item in data):
                    return [''.join(item) for item in data]
            return data

        # تحويل البيانات من JSON إلى كائنات Python
        header_info = json.loads(sample.header_info) if sample.header_info else {}
        sections_info = json.loads(sample.sections_info) if sample.sections_info else []
        imports_info = json.loads(sample.imports_info) if sample.imports_info else {}
        dynamic_indicators = json.loads(sample.dynamic_indicators) if sample.dynamic_indicators else {}
        strings = json.loads(sample.strings) if sample.strings else []
        binwalk_results = json.loads(sample.binwalk_results) if sample.binwalk_results else []
        network_indicators = json.loads(sample.network_indicators) if sample.network_indicators else {}
        yara_matches = json.loads(sample.yara_matches) if sample.yara_matches else []
        libraries = json.loads(sample.libraries) if sample.libraries else []
        powershell_commands = json.loads(sample.powershell_commands) if sample.powershell_commands else []
        persistence_indicators = json.loads(sample.persistence_indicators) if sample.persistence_indicators else []
        c2_indicators = json.loads(sample.c2_indicators) if sample.c2_indicators else []
        mitre_techniques = json.loads(sample.mitre_techniques) if sample.mitre_techniques else []

        # إصلاح: معالجة المكتبات والأوامر
        libraries = fix_data(libraries)
        powershell_commands = fix_data(powershell_commands)
        persistence_indicators = fix_data(persistence_indicators)
        c2_indicators = fix_data(c2_indicators)

        # إضافة متغير sandbox_report فارغ لتجنب الأخطاء في القالب
        sandbox_report = {}

        return render_template(
            'shared_report.html',
            sample=sample,
            header_info=header_info,
            sections_info=sections_info,
            imports_info=imports_info,
            dynamic_indicators=dynamic_indicators,
            sandbox_report=sandbox_report,
            strings=strings,
            binwalk_results=binwalk_results,
            entropy=sample.entropy,
            packed=sample.packed,
            network_indicators=network_indicators,
            yara_matches=yara_matches,
            libraries=libraries,
            powershell_commands=powershell_commands,
            persistence_indicators=persistence_indicators,
            c2_indicators=c2_indicators,
            mitre_techniques=mitre_techniques
        )
    except Exception as e:
        flash(f'خطأ في تحميل التقرير المشترك: {str(e)}', 'error')
        app.logger.error(f"خطأ في تحميل التقرير المشترك: {str(e)}")
        return redirect(url_for('index'))


@app.route('/generate_pdf/<int:sample_id>')
@login_required
def generate_pdf(sample_id):
    try:
        sample = AnalysisSample.query.get_or_404(sample_id)

        # إصلاح: معالجة البيانات المخزنة قبل العرض
        def fix_data(data):
            if isinstance(data, list):
                if all(isinstance(item, list) for item in data):
                    return [''.join(item) for item in data]
            return data

        # تحويل البيانات من JSON إلى كائنات Python
        header_info = json.loads(sample.header_info) if sample.header_info else {}
        sections_info = json.loads(sample.sections_info) if sample.sections_info else []
        imports_info = json.loads(sample.imports_info) if sample.imports_info else {}
        dynamic_indicators = json.loads(sample.dynamic_indicators) if sample.dynamic_indicators else {}
        strings = json.loads(sample.strings) if sample.strings else {}
        binwalk_results = json.loads(sample.binwalk_results) if sample.binwalk_results else []
        network_indicators = json.loads(sample.network_indicators) if sample.network_indicators else {}
        yara_matches = json.loads(sample.yara_matches) if sample.yara_matches else []
        libraries = json.loads(sample.libraries) if sample.libraries else []
        powershell_commands = json.loads(sample.powershell_commands) if sample.powershell_commands else []
        persistence_indicators = json.loads(sample.persistence_indicators) if sample.persistence_indicators else []
        c2_indicators = json.loads(sample.c2_indicators) if sample.c2_indicators else []
        mitre_techniques = json.loads(sample.mitre_techniques) if sample.mitre_techniques else []

        # إصلاح: معالجة المكتبات والأوامر
        libraries = fix_data(libraries)
        powershell_commands = fix_data(powershell_commands)
        persistence_indicators = fix_data(persistence_indicators)
        c2_indicators = fix_data(c2_indicators)

        # إضافة متغير sandbox_report فارغ لتجنب الأخطاء في القالب
        sandbox_report = {}

        # توليد محتوى HTML للتقرير
        html_content = render_template(
            'report.html',
            sample=sample,
            header_info=header_info,
            sections_info=sections_info,
            imports_info=imports_info,
            dynamic_indicators=dynamic_indicators,
            sandbox_report=sandbox_report,
            strings=strings,
            binwalk_results=binwalk_results,
            entropy=sample.entropy,
            packed=sample.packed,
            network_indicators=network_indicators,
            yara_matches=yara_matches,
            libraries=libraries,
            powershell_commands=powershell_commands,
            persistence_indicators=persistence_indicators,
            c2_indicators=c2_indicators,
            mitre_techniques=mitre_techniques,
            pdf_mode=True
        )

        # توليد ملف PDF
        pdf_filename = f"report_{sample.id}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.pdf"
        pdf_path = generate_pdf_report(html_content, pdf_filename)

        if pdf_path:
            # حذف ملف PDF بعد إرساله
            try:
                return send_file(
                    pdf_path,
                    as_attachment=True,
                    download_name=f"تقرير_تحليل_{sample.filename}.pdf",
                    on_close=lambda: safe_delete(pdf_path)
                )
            except Exception as e:
                flash(f'خطأ في إرسال ملف PDF: {str(e)}', 'error')
                app.logger.error(f"خطأ في إرسال ملف PDF: {str(e)}")
                safe_delete(pdf_path)
                return redirect(url_for('sample_detail', sample_id=sample_id))
        else:
            flash('فشل في توليد ملف PDF', 'error')
            return redirect(url_for('sample_detail', sample_id=sample_id))
    except Exception as e:
        flash(f'خطأ في توليد ملف PDF: {str(e)}', 'error')
        app.logger.error(f"خطأ في توليد ملف PDF: {str(e)}")
        return redirect(url_for('sample_detail', sample_id=sample_id))


@app.route('/share_sample/<int:sample_id>', methods=['POST'])
@login_required
def share_sample(sample_id):
    try:
        expiry_days = int(request.form.get('expiry_days', 7))
        token = create_share_link(sample_id, expiry_days)

        if token:
            share_url = url_for('shared_report', token=token, _external=True)
            return jsonify({
                'success': True,
                'share_url': share_url,
                'expiry': (datetime.utcnow() + timedelta(days=expiry_days)).strftime('%Y-%m-%d %H:%M:%S')
            })
        else:
            return jsonify({'success': False, 'message': 'العينة غير موجودة'})
    except Exception as e:
        app.logger.error(f"خطأ في مشاركة العينة: {str(e)}")
        return jsonify({'success': False, 'message': f'حدث خطأ: {str(e)}'})


@app.route('/dashboard')
@login_required
def dashboard():
    try:
        # إحصائيات تحليل البرمجيات الخبيثة للمستخدم الحالي
        user_samples = AnalysisSample.query.filter_by(user_id=current_user.id)
        total_samples = user_samples.count()
        malicious_samples = user_samples.filter_by(is_malicious=True).count()
        benign_samples = total_samples - malicious_samples
        latest_samples = user_samples.order_by(AnalysisSample.upload_date.desc()).limit(10).all()

        # إحصائيات تحليلات أمن الويب للمستخدم الحالي
        user_web_analyses = WebAnalysis.query.filter_by(user_id=current_user.id)
        web_analyses_count = user_web_analyses.count()
        safe_domains = user_web_analyses.filter(WebAnalysis.vulnerable_links == 0).count()
        vulnerabilities_count = db.session.query(
            db.func.sum(WebAnalysis.vulnerable_links)
        ).filter(WebAnalysis.user_id == current_user.id).scalar() or 0
        vulnerable_domains = user_web_analyses.filter(WebAnalysis.vulnerable_links > 0).count()
        latest_web_analyses = user_web_analyses.order_by(WebAnalysis.scan_date.desc()).limit(10).all()

        # إحصائيات تحليلات الروابط للمستخدم الحالي
        user_url_analyses = URLAnalysis.query.filter_by(user_id=current_user.id)
        url_analyses_count = user_url_analyses.count()
        malicious_urls = user_url_analyses.filter_by(is_malicious=True).count()
        safe_urls = url_analyses_count - malicious_urls
        latest_url_analyses = user_url_analyses.order_by(URLAnalysis.scan_date.desc()).limit(10).all()

        # إحصائيات تحليل الكود للمستخدم الحالي
        user_code_analyses = CodeAnalysis.query.filter_by(user_id=current_user.id)
        code_analyses_count = user_code_analyses.count()
        vulnerable_code = user_code_analyses.filter(CodeAnalysis.vulnerabilities != '[]').count()
        secure_code = code_analyses_count - vulnerable_code
        latest_code_analyses = user_code_analyses.order_by(CodeAnalysis.analysis_date.desc()).limit(10).all()

        # إحصائيات PDF
        user_pdf_analyses = PDFAnalysis.query.filter_by(user_id=current_user.id)
        pdf_analyses_count = user_pdf_analyses.count()
        malicious_pdfs = user_pdf_analyses.filter_by(is_malicious=True).count()
        safe_pdfs = pdf_analyses_count - malicious_pdfs
        latest_pdf_analyses = user_pdf_analyses.order_by(PDFAnalysis.upload_date.desc()).limit(5).all()
        # إحصائيات تحليلات الصور
        user_image_analyses = ImageAnalysis.query.filter_by(user_id=current_user.id)
        image_analyses_count = user_image_analyses.count()
        malicious_images = user_image_analyses.filter_by(is_malicious=True).count()
        safe_images = image_analyses_count - malicious_images
        latest_image_analyses = user_image_analyses.order_by(ImageAnalysis.upload_date.desc()).limit(10).all()

        return render_template(
            'dashboard.html',
            # بيانات البرمجيات الخبيثة
            total_samples=total_samples,
            malicious_samples=malicious_samples,
            benign_samples=benign_samples,
            latest_samples=latest_samples,

            # بيانات أمن الويب
            web_analyses_count=web_analyses_count,
            safe_domains=safe_domains,
            vulnerabilities_count=vulnerabilities_count,
            web_analyses=latest_web_analyses,
            vulnerable_domains=vulnerable_domains,

            # بيانات تحليل الروابط
            url_analyses_count=url_analyses_count,
            malicious_urls=malicious_urls,
            safe_urls=safe_urls,
            url_analyses=latest_url_analyses,

            # بيانات تحليل الكود
            code_analyses_count=code_analyses_count,
            vulnerable_code=vulnerable_code,
            secure_code=secure_code,
            code_analyses=latest_code_analyses,
            # إحصائيات PDF الجديدة
            pdf_analyses_count=pdf_analyses_count,
            malicious_pdfs=malicious_pdfs,
            safe_pdfs=safe_pdfs,
            latest_pdf_analyses=latest_pdf_analyses,
            # إحصائيات الصور الجديدة
            image_analyses_count=image_analyses_count,
            malicious_images=malicious_images,
            safe_images=safe_images,
            latest_image_analyses=latest_image_analyses


        )
    except Exception as e:
        flash(f'خطأ في تحميل لوحة التحكم: {str(e)}', 'error')
        app.logger.error(f"خطأ في تحميل لوحة التحكم: {str(e)}")
        return redirect(url_for('index'))

# إضافة معلومات الإشعارات إلى context لكل صفحة
@app.context_processor
def inject_notification_data():
    if current_user.is_authenticated:
        unread_count = count_unread_notifications(current_user.id)
        return {'unread_notifications_count': unread_count}
    return {'unread_notifications_count': 0}

@app.route('/logout')
@login_required
def logout():
    try:
        logout_user()
        return redirect(url_for('index'))
    except Exception as e:
        flash(f'خطأ في تسجيل الخروج: {str(e)}', 'error')
        app.logger.error(f"خطأ في تسجيل الخروج: {str(e)}")
        return redirect(url_for('index'))
@app.route('/contact')
def contact():
    return render_template('contact.html')

import os
from werkzeug.utils import secure_filename
from flask import request, jsonify, flash, redirect, url_for, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from forms import ProfileForm, PasswordForm, SettingsForm

# الإعدادات
UPLOAD_FOLDER = 'static/uploads/profiles'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 2 * 1024 * 1024  # 2MB


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/settings_test')
def settings_test():
    return render_template('settings_test.html')

@app.route('/settings')
@login_required
def settings():
    profile_form = ProfileForm()
    password_form = PasswordForm()
    settings_form = SettingsForm()

    # تعبئة النماذج ببيانات المستخدم الحالية
    profile_form.username.data = current_user.username
    profile_form.email.data = current_user.email

    # تحميل الإعدادات المحفوظة إذا وجدت
    user_settings = UserSettings.query.filter_by(user_id=current_user.id).first()
    if user_settings:
        settings_form.language.data = user_settings.language
        settings_form.time_format.data = user_settings.time_format
        settings_form.email_notifications.data = user_settings.email_notifications
        settings_form.security_notifications.data = user_settings.security_notifications
        settings_form.app_notifications.data = user_settings.app_notifications
        settings_form.newsletter.data = user_settings.newsletter
        settings_form.private_account.data = user_settings.private_account
        settings_form.secure_login.data = user_settings.secure_login
        settings_form.analytics.data = user_settings.analytics

    return render_template('settings-redesigned.html',
                           profile_form=profile_form,
                           password_form=password_form,
                           settings_form=settings_form,
                           user_settings=user_settings)


@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    try:
        username = request.form.get('username')
        email = request.form.get('email')

        if not all([username, email]):
            return jsonify({'success': False, 'message': 'جميع الحقول مطلوبة'})

        # التحقق من أن البريد الإلكتروني فريد (إذا تم تغييره)
        if email != current_user.email:
            existing_user = User.query.filter_by(email=email).first()
            if existing_user and existing_user.id != current_user.id:
                return jsonify({'success': False, 'message': 'البريد الإلكتروني مستخدم بالفعل'})

        # التحقق من أن اسم المستخدم فريد (إذا تم تغييره)
        if username != current_user.username:
            existing_user = User.query.filter_by(username=username).first()
            if existing_user and existing_user.id != current_user.id:
                return jsonify({'success': False, 'message': 'اسم المستخدم مستخدم بالفعل'})

        # تحديث بيانات المستخدم
        current_user.username = username
        current_user.email = email

        # معالجة رفع الصورة إذا وجدت
        if 'avatar' in request.files:
            file = request.files['avatar']
            if file and file.filename != '' and allowed_file(file.filename):
                if file.content_length > MAX_FILE_SIZE:
                    return jsonify({'success': False, 'message': 'حجم الملف يجب أن يكون أقل من 2MB'})

                # إنشاء مجلد التحميل إذا لم يكن موجوداً
                os.makedirs(UPLOAD_FOLDER, exist_ok=True)

                # إنشاء اسم ملف فريد
                filename = secure_filename(
                    f"{current_user.id}_{datetime.now().timestamp()}.{file.filename.rsplit('.', 1)[1].lower()}")
                filepath = os.path.join(UPLOAD_FOLDER, filename)

                # حفظ الملف
                file.save(filepath)

                # حذف الصورة القديمة إذا كانت موجودة
                if current_user.profile_image and os.path.exists(
                        os.path.join(UPLOAD_FOLDER, current_user.profile_image)):
                    os.remove(os.path.join(UPLOAD_FOLDER, current_user.profile_image))

                current_user.profile_image = filename

        db.session.commit()

        return jsonify({'success': True, 'message': 'تم تحديث الملف الشخصي بنجاح'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'حدث خطأ أثناء تحديث الملف الشخصي'})


@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    try:
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not all([current_password, new_password, confirm_password]):
            return jsonify({'success': False, 'message': 'جميع الحقول مطلوبة'})

        if new_password != confirm_password:
            return jsonify({'success': False, 'message': 'كلمة المرور غير متطابقة'})

        if not check_password_hash(current_user.password, current_password):
            return jsonify({'success': False, 'message': 'كلمة المرور الحالية غير صحيحة'})

        current_user.password = generate_password_hash(new_password)
        db.session.commit()

        return jsonify({'success': True, 'message': 'تم تغيير كلمة المرور بنجاح'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'حدث خطأ أثناء تغيير كلمة المرور'})


@app.route('/update_settings', methods=['POST'])
@login_required
def update_settings():
    try:
        # استقبال البيانات من النموذج
        language = request.form.get('language')
        time_format = request.form.get('time_format')
        email_notifications = request.form.get('email_notifications') == 'on'
        security_notifications = request.form.get('security_notifications') == 'on'
        app_notifications = request.form.get('app_notifications') == 'on'
        newsletter = request.form.get('newsletter') == 'on'
        private_account = request.form.get('private_account') == 'on'
        secure_login = request.form.get('secure_login') == 'on'
        analytics = request.form.get('analytics') == 'on'

        # البحث عن إعدادات المستخدم أو إنشاؤها إذا لم تكن موجودة
        user_settings = UserSettings.query.filter_by(user_id=current_user.id).first()
        if not user_settings:
            user_settings = UserSettings(user_id=current_user.id)
            db.session.add(user_settings)

        # تحديث الإعدادات
        user_settings.language = language
        user_settings.time_format = time_format
        user_settings.email_notifications = email_notifications
        user_settings.security_notifications = security_notifications
        user_settings.app_notifications = app_notifications
        user_settings.newsletter = newsletter
        user_settings.private_account = private_account
        user_settings.secure_login = secure_login
        user_settings.analytics = analytics

        db.session.commit()

        return jsonify({'success': True, 'message': 'تم تحديث الإعدادات بنجاح'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'حدث خطأ أثناء تحديث الإعدادات'})


@app.route('/api/generate-key', methods=['POST'])
@login_required
@csrf.exempt  # تعطيل حماية CSRF لهذا المسار
def generate_api_key():
    try:
        import secrets
        # توليد مفتاح API عشوائي آمن وفريد
        max_attempts = 10
        api_key = None
        
        for _ in range(max_attempts):
            temp_key = 'sk_' + secrets.token_urlsafe(32)
            # التحقق من عدم وجود المفتاح
            existing = User.query.filter_by(api_key=temp_key).first()
            if not existing:
                api_key = temp_key
                break
        
        if not api_key:
            return jsonify({
                'success': False,
                'message': 'فشل في توليد مفتاح فريد، حاول مرة أخرى'
            })
        
        # تحديث مفتاح المستخدم
        current_user.api_key = api_key
        db.session.commit()
        
        return jsonify({
            'success': True,
            'api_key': api_key,
            'message': 'تم توليد مفتاح API بنجاح'
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"خطأ في توليد مفتاح API: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'حدث خطأ أثناء توليد مفتاح API'
        })


@app.route('/api/test', methods=['GET'])
def test_api():
    return jsonify({
        'success': True,
        'message': 'الاتصال بالاي بي آي يعمل بشكل صحيح',
        'time': str(datetime.now())
    })


@app.route('/api/revoke-key', methods=['POST'])
@login_required
@csrf.exempt  # تعطيل حماية CSRF لهذا المسار
def revoke_api_key():
    try:
        # إلغاء مفتاح API للمستخدم الحالي
        current_user.api_key = None
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'تم إلغاء مفتاح API بنجاح'
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"خطأ في إلغاء مفتاح API: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'حدث خطأ أثناء إلغاء مفتاح API'
        })







@app.errorhandler(413)
def request_entity_too_large(error):
    max_size_mb = app.config['MAX_FILE_SIZE'] // (1024 * 1024)
    flash(f'حجم الملف كبير جداً، الحد الأقصى {max_size_mb}MB', 'error')
    return redirect(url_for('index'))


@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(error):
    app.logger.error(f"خطأ في الخادم: {str(error)}")
    return render_template('500.html'), 500


@app.errorhandler(Exception)
def handle_exception(e):
    app.logger.error(f"حدث خطأ غير متوقع: {str(e)}")
    # صفحة خطأ احتياطية في حالة عدم وجود قالب error.html
    error_html = f"""
    <!DOCTYPE html>
    <html lang="ar" dir="rtl">
    <head>
        <meta charset="UTF-8">
        <title>خطأ في النظام</title>
        <style>
            body {{ font-family: Tahoma; text-align: center; padding: 50px; }}
            h1 {{ color: #d9534f; }}
            .error-details {{ 
                background: #f8d7da; 
                border: 1px solid #f5c6cb; 
                padding: 20px; 
                margin: 20px auto; 
                max-width: 800px;
                text-align: right;
            }}
        </style>
    </head>
    <body>
        <h1>⚠️ حدث خطأ غير متوقع</h1>
        <p>نعتذر عن الإزعاج، يرجى المحاولة مرة أخرى لاحقاً</p>

        <div class="error-details">
            <strong>تفاصيل الخطأ:</strong><br>
            {str(e)}
        </div>

        <p>
            <a href="{{ url_for('index') }}" style="color: #004085;">Return to Home Page</a>
        </p>
    </body>
    </html>
    """

    return error_html, 500

from sqlalchemy import func
from datetime import datetime, timedelta
from flask import render_template, request, flash, redirect, url_for, abort
from flask_login import login_required, current_user
from sqlalchemy import func
from models import User, AnalysisSample, WebAnalysis, URLAnalysis, PDFAnalysis, CodeAnalysis


# ... (بقية الاستيرادات والتكوين)

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        abort(403)

    try:
        # الحصول على معاملات الفلترة من الـ request
        analysis_type = request.args.get('analysis_type', 'all')
        user_id = request.args.get('user_id', 'all')
        time_range = request.args.get('time_range', 'all')

        # تحديد الفترة الزمنية
        today = datetime.utcnow().date()
        if time_range == 'today':
            start_date = datetime.combine(today, datetime.min.time())
        elif time_range == 'week':
            start_date = datetime.utcnow() - timedelta(days=7)
        elif time_range == 'month':
            start_date = datetime.utcnow() - timedelta(days=30)
        else:
            start_date = None

        # إحصائيات المستخدمين
        total_users = User.query.count()
        active_users = User.query.filter(User.last_login >= (datetime.utcnow() - timedelta(days=7))).count()
        admin_users = User.query.filter_by(is_admin=True).count()

        # إحصائيات العينات
        total_samples = AnalysisSample.query.count()
        malicious_samples = AnalysisSample.query.filter_by(is_malicious=True).count()
        benign_samples = total_samples - malicious_samples

        # إحصائيات تحليلات الويب
        web_analyses_count = WebAnalysis.query.count()
        vulnerable_domains = WebAnalysis.query.filter(WebAnalysis.vulnerable_links > 0).count()

        # إحصائيات تحليلات الروابط
        url_analyses_count = URLAnalysis.query.count()
        malicious_urls = URLAnalysis.query.filter_by(is_malicious=True).count()

        # إحصائيات تحليلات PDF
        total_pdf_analyses = PDFAnalysis.query.count()
        malicious_pdfs = PDFAnalysis.query.filter_by(is_malicious=True).count()
        safe_pdfs = total_pdf_analyses - malicious_pdfs

        # حساب النسب المئوية لتحليلات PDF
        safe_pdfs_percentage = round((safe_pdfs / total_pdf_analyses * 100), 2) if total_pdf_analyses > 0 else 0
        malicious_pdfs_percentage = round((malicious_pdfs / total_pdf_analyses * 100),
                                          2) if total_pdf_analyses > 0 else 0

        # تحليلات PDF اليوم
        pdf_analyses_today = PDFAnalysis.query.filter(func.date(PDFAnalysis.scan_date) == today).count()

        # إحصائيات تحليلات الكود
        code_analyses_count = CodeAnalysis.query.count()
        code_analyses_today = CodeAnalysis.query.filter(func.date(CodeAnalysis.analysis_date) == today).count()

        # إحصائيات تحليلات الصور
        image_analyses_count = ImageAnalysis.query.count()
        safe_images = ImageAnalysis.query.filter_by(is_malicious=False).count()
        malicious_images = ImageAnalysis.query.filter_by(is_malicious=True).count()

        # التحليلات اليومية الأخرى
        file_analyses_today = AnalysisSample.query.filter(func.date(AnalysisSample.upload_date) == today).count()
        web_analyses_today = WebAnalysis.query.filter(func.date(WebAnalysis.scan_date) == today).count()
        url_analyses_today = URLAnalysis.query.filter(func.date(URLAnalysis.scan_date) == today).count()

        # إحصائيات المستخدمين والتحليلات
        all_users = User.query.all()
        users_stats = []
        for user in all_users:
            file_analyses = AnalysisSample.query.filter_by(user_id=user.id).count()
            web_analyses = WebAnalysis.query.filter_by(user_id=user.id).count()
            url_analyses = URLAnalysis.query.filter_by(user_id=user.id).count()
            code_analyses = CodeAnalysis.query.filter_by(user_id=user.id).count()
            pdf_analyses = PDFAnalysis.query.filter_by(user_id=user.id).count()

            total_analyses = file_analyses + web_analyses + url_analyses + code_analyses + pdf_analyses

            users_stats.append({
                'username': user.username,
                'is_admin': user.is_admin,
                'file_analyses': file_analyses,
                'web_analyses': web_analyses,
                'url_analyses': url_analyses,
                'code_analyses': code_analyses,
                'pdf_analyses': pdf_analyses,
                'total_analyses': total_analyses
            })

        # آخر المستخدمين المسجلين
        latest_users = User.query.order_by(User.created_at.desc()).limit(5).all()

        # تطبيق الفلاتر على التحليلات
        # أحدث العينات المفحوصة
        samples_query = AnalysisSample.query
        if user_id != 'all':
            samples_query = samples_query.filter_by(user_id=int(user_id))
        if start_date:
            samples_query = samples_query.filter(AnalysisSample.upload_date >= start_date)
        latest_samples = samples_query.order_by(AnalysisSample.upload_date.desc()).limit(10).all() if analysis_type in ['all', 'file'] else []

        # أحدث تحليلات الويب
        web_query = WebAnalysis.query
        if user_id != 'all':
            web_query = web_query.filter_by(user_id=int(user_id))
        if start_date:
            web_query = web_query.filter(WebAnalysis.scan_date >= start_date)
        latest_web_analyses = web_query.order_by(WebAnalysis.scan_date.desc()).limit(10).all() if analysis_type in ['all', 'web'] else []

        # أحدث تحليلات الروابط
        url_query = URLAnalysis.query
        if user_id != 'all':
            url_query = url_query.filter_by(user_id=int(user_id))
        if start_date:
            url_query = url_query.filter(URLAnalysis.scan_date >= start_date)
        latest_url_analyses = url_query.order_by(URLAnalysis.scan_date.desc()).limit(10).all() if analysis_type in ['all', 'url'] else []

        # أحدث تحليلات PDF
        pdf_query = PDFAnalysis.query
        if user_id != 'all':
            pdf_query = pdf_query.filter_by(user_id=int(user_id))
        if start_date:
            pdf_query = pdf_query.filter(PDFAnalysis.scan_date >= start_date)
        latest_pdf_analyses = pdf_query.order_by(PDFAnalysis.scan_date.desc()).limit(10).all() if analysis_type in ['all', 'pdf'] else []

        # أحدث تحليلات الكود
        code_query = CodeAnalysis.query
        if user_id != 'all':
            code_query = code_query.filter_by(user_id=int(user_id))
        if start_date:
            code_query = code_query.filter(CodeAnalysis.analysis_date >= start_date)
        latest_code_analyses = code_query.order_by(CodeAnalysis.analysis_date.desc()).limit(10).all() if analysis_type in ['all', 'code'] else []

        # أحدث تحليلات الصور
        image_query = ImageAnalysis.query
        if user_id != 'all':
            image_query = image_query.filter_by(user_id=int(user_id))
        if start_date:
            image_query = image_query.filter(ImageAnalysis.upload_date >= start_date)
        latest_image_analyses = image_query.order_by(ImageAnalysis.upload_date.desc()).limit(10).all() if analysis_type in ['all', 'image'] else []

        # إحصائيات الإشعارات
        notifications_count = Notification.query.count()
        global_notifications_count = Notification.query.filter_by(is_global=True).count()

        return render_template(
            'admin_dashboard.html',
            # إحصائيات المستخدمين
            total_users=total_users,
            active_users=active_users,
            admin_users=admin_users,

            # إحصائيات العينات
            total_samples=total_samples,
            malicious_samples=malicious_samples,
            benign_samples=benign_samples,
            file_analyses_count=total_samples,

            # إحصائيات الويب
            web_analyses_count=web_analyses_count,
            vulnerable_domains=vulnerable_domains,
            safe_domains=web_analyses_count - vulnerable_domains,

            # إحصائيات الروابط
            url_analyses_count=url_analyses_count,
            malicious_urls=malicious_urls,
            safe_urls=url_analyses_count - malicious_urls,

            # إحصائيات PDF
            total_pdf_analyses=total_pdf_analyses,
            malicious_pdfs=malicious_pdfs,
            safe_pdfs=safe_pdfs,
            safe_pdfs_percentage=safe_pdfs_percentage,
            malicious_pdfs_percentage=malicious_pdfs_percentage,
            pdf_analyses_today=pdf_analyses_today,
            pdf_analyses_count=total_pdf_analyses,

            # إحصائيات الكود
            code_analyses_count=code_analyses_count,
            code_analyses_today=code_analyses_today,
            secure_code=code_analyses_count - CodeAnalysis.query.filter(CodeAnalysis.vulnerabilities != '[]').count(),
            vulnerable_code=CodeAnalysis.query.filter(CodeAnalysis.vulnerabilities != '[]').count(),

            # إحصائيات الصور
            image_analyses_count=image_analyses_count,
            safe_images=safe_images,
            malicious_images=malicious_images,

            # التحليلات اليومية
            file_analyses_today=file_analyses_today,
            web_analyses_today=web_analyses_today,
            url_analyses_today=url_analyses_today,

            # إحصائيات الثغرات
            vulnerabilities_count=WebAnalysis.query.filter(WebAnalysis.vulnerable_links > 0).count(),

            # إحصائيات الإشعارات
            notifications_count=notifications_count,
            global_notifications_count=global_notifications_count,

            # إحصائيات المستخدمين والتحليلات
            users_stats=users_stats,
            all_users=all_users,

            # القوائم
            latest_users=latest_users,
            latest_samples=latest_samples,
            web_analyses=latest_web_analyses,
            latest_web_analyses=latest_web_analyses,
            url_analyses=latest_url_analyses,
            latest_url_analyses=latest_url_analyses,
            latest_pdf_analyses=latest_pdf_analyses,
            code_analyses=latest_code_analyses,
            latest_image_analyses=latest_image_analyses
        )
    except Exception as e:
        flash(f'خطأ في تحميل لوحة التحكم: {str(e)}', 'error')
        app.logger.error(f"خطأ في تحميل لوحة التحكم: {str(e)}")
        return redirect(url_for('dashboard'))

@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        abort(403)

    users = User.query.all()
    return render_template('admin_users.html', users=users)


@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        abort(403)

    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('لا يمكن حذف حسابك الخاص!', 'danger')
        return redirect(url_for('admin_users'))

    try:
        # حذف جميع بيانات المستخدم
        AnalysisSample.query.filter_by(user_id=user_id).delete()
        WebAnalysis.query.filter_by(user_id=user_id).delete()
        URLAnalysis.query.filter_by(user_id=user_id).delete()

        db.session.delete(user)
        db.session.commit()
        flash('تم حذف المستخدم بنجاح', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'حدث خطأ أثناء حذف المستخدم: {str(e)}', 'danger')

    return redirect(url_for('admin_users'))


@app.route('/admin/toggle_admin/<int:user_id>', methods=['POST'])
@login_required
def toggle_admin(user_id):
    if not current_user.is_admin:
        abort(403)

    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('لا يمكن تعديل صلاحيات حسابك الخاص!', 'danger')
        return redirect(url_for('admin_users'))

    try:
        user.is_admin = not user.is_admin
        db.session.commit()
        status = "مسؤول" if user.is_admin else "مستخدم عادي"
        flash(f'تم تغيير صلاحية المستخدم إلى {status}', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'حدث خطأ أثناء تعديل الصلاحيات: {str(e)}', 'danger')

    return redirect(url_for('admin_users'))

model = joblib.load("models/models_web_c_a/security_model.pkl")
vectorizer = joblib.load("models/models_web_c_a/vectorizer.pkl")


@app.route('/web_code_analysis', methods=['GET', 'POST'])
@login_required  # إذا كان التطبيق يتطلب تسجيل دخول
def web_code_analysis():
    result = None
    code = ""
    url_error = None
    selected_input_type = "code"
    analysis_id = None

    if request.method == 'POST':
        input_type = request.form.get('input_type', 'code')
        selected_input_type = input_type
        uploaded_file = request.files.get('file')

        if input_type == 'code':
            code = request.form.get('code', '')

        elif input_type == 'url':
            url = request.form.get('url', '')
            if not url:
                url_error = "يرجى إدخال رابط صحيح."
            else:
                try:
                    response = requests.get(url, timeout=7, verify=False)
                    response.raise_for_status()
                    code = response.text
                except Exception as e:
                    url_error = f"فشل في جلب المحتوى من الرابط: {str(e)}"

        elif input_type == 'file' and uploaded_file and uploaded_file.filename != '':
            try:
                code = uploaded_file.read().decode(errors='ignore')
            except Exception as e:
                url_error = f"خطأ في قراءة الملف: {str(e)}"

        if code and not url_error:
            try:
                vectorized_code = vectorizer.transform([code])
                prediction_proba = model.predict_proba(vectorized_code)[0]
                labels = model.classes_

                predictions = {label: round(prob * 100, 2) for label, prob in zip(labels, prediction_proba)}
                sorted_probs = dict(sorted(predictions.items(), key=lambda item: item[1], reverse=True))

                result = {
                    "predictions": sorted_probs,
                    "total_flags": len([v for v in sorted_probs.values() if v > 30]),
                    "confidence": max(predictions.values()) if predictions else 0,
                }

                # تحليل الكود لاكتشاف الثغرات الشائعة
                vulnerabilities = detect_vulnerabilities(code)

                # حفظ التحليل في قاعدة البيانات
                code_analysis = CodeAnalysis(
                    analysis_type=input_type,
                    content=code,
                    user_id=current_user.id if current_user.is_authenticated else None
                )
                code_analysis.set_model_predictions(result)
                code_analysis.set_vulnerabilities(vulnerabilities)

                db.session.add(code_analysis)
                db.session.commit()
                analysis_id = code_analysis.id

                # Redirect to report page with data
                return redirect(url_for('report_web_code_analysis', analysis_id=analysis_id))

            except Exception as e:
                flash(f"خطأ في التنبؤ: {str(e)}", 'error')

    return render_template("web_code_analysis.html",
                           code=code,
                           url_error=url_error,
                           selected_input_type=selected_input_type)


def detect_vulnerabilities(code):
    """اكتشاف الثغرات الأمنية في الكود"""
    vulnerabilities = []

    # اكتشاف حقن SQL
    sql_patterns = [r"SELECT\s.*?\sFROM", r"INSERT\sINTO", r"UPDATE\s.*?\sSET", r"DELETE\sFROM"]
    if any(re.search(pattern, code, re.IGNORECASE) for pattern in sql_patterns):
        if not re.search(r"prepare\(", code, re.IGNORECASE):
            vulnerabilities.append({
                "name": "حقن SQL",
                "description": "تم اكتشاف استعلامات SQL مباشرة دون استخدام استعلامات معلمة",
                "severity": "عالي",
                "solution": "استخدام استعلامات معلمة (Prepared Statements) لمنع هجمات حقن SQL"
            })

    # اكتشاف XSS
    if re.search(r"echo\s*\$_GET|echo\s*\$_POST|echo\s*\$_REQUEST", code):
        if not re.search(r"htmlspecialchars\(", code):
            vulnerabilities.append({
                "name": "XSS (Cross-Site Scripting)",
                "description": "إخراج بيانات المستخدم دون تصفية",
                "severity": "متوسط",
                "solution": "استخدام htmlspecialchars() أو فلترة المدخلات قبل الإخراج"
            })

    # اكتشاف مشاكل جلسات
    if re.search(r"session_start\(", code) and not re.search(r"session_regenerate_id\(", code):
        vulnerabilities.append({
            "name": "تثبيت الجلسة",
            "description": "عدم تجديد معرف الجلسة بعد التسجيل",
            "severity": "متوسط",
            "solution": "استخدام session_regenerate_id(true) بعد تسجيل الدخول"
        })

    return vulnerabilities


# نقاط النهاية لحذف التقارير
@app.route('/delete_sample_report/<int:sample_id>', methods=['DELETE'])
@login_required
def delete_sample_report(sample_id):
    try:
        sample = AnalysisSample.query.get_or_404(sample_id)

        if sample.user_id != current_user.id and not current_user.is_admin:
            return jsonify({
                'success': False,
                'message': 'غير مصرح لك بحذف هذا التقرير'
            }), 403

        db.session.delete(sample)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'تم حذف التقرير بنجاح'
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"خطأ في حذف التقرير: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'حدث خطأ أثناء حذف التقرير: {str(e)}'
        }), 500


@app.route('/delete_web_report/<int:analysis_id>', methods=['DELETE'])
@login_required
def delete_web_report(analysis_id):
    try:
        analysis = WebAnalysis.query.get_or_404(analysis_id)

        if analysis.user_id != current_user.id and not current_user.is_admin:
            return jsonify({
                'success': False,
                'message': 'غير مصرح لك بحذف هذا التقرير'
            }), 403

        db.session.delete(analysis)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'تم حذف التقرير بنجاح'
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"خطأ في حذف التقرير: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'حدث خطأ أثناء حذف التقرير: {str(e)}'
        }), 500


@app.route('/delete_url_report/<int:analysis_id>', methods=['DELETE'])
@login_required
def delete_url_report(analysis_id):
    try:
        analysis = URLAnalysis.query.get_or_404(analysis_id)

        if analysis.user_id != current_user.id and not current_user.is_admin:
            return jsonify({
                'success': False,
                'message': 'غير مصرح لك بحذف هذا التقرير'
            }), 403

        db.session.delete(analysis)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'تم حذف التقرير بنجاح'
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"خطأ في حذف التقرير: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'حدث خطأ أثناء حذف التقرير: {str(e)}'
        }), 500


@app.route('/delete_code_report/<int:analysis_id>', methods=['DELETE'])
@login_required
def delete_code_report(analysis_id):
    try:
        analysis = CodeAnalysis.query.get_or_404(analysis_id)

        if analysis.user_id != current_user.id and not current_user.is_admin:
            return jsonify({
                'success': False,
                'message': 'غير مصرح لك بحذف هذا التقرير'
            }), 403

        db.session.delete(analysis)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'تم حذف التقرير بنجاح'
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"خطأ في حذف التقرير: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'حدث خطأ أثناء حذف التقرير: {str(e)}'
        }), 500
@app.route('/report_web_code_analysis/<int:analysis_id>', methods=['GET', 'POST'])
def report_web_code_analysis(analysis_id):
    analysis = CodeAnalysis.query.get_or_404(analysis_id)
    code = analysis.content
    result = analysis.get_model_predictions()
    vulnerabilities = analysis.get_vulnerabilities()

    graphJSON = None
    if result and 'predictions' in result:
        labels = list(result['predictions'].keys())
        values = list(result['predictions'].values())

        fig = go.Figure(data=[go.Pie(labels=labels, values=values, hole=0.3)])
        fig.update_layout(
            title='توزيع الثغرات الأمنية',
            font=dict(family="Arial", size=12, color="#7f7f7f")
        )

        # الحل: استخدام plotly.io.to_json مباشرةً
        import plotly.io as pio
        graphJSON = pio.to_json(fig)  # ✅ الطريقة الصحيحة

    if request.method == 'POST' and 'generate_pdf' in request.form:
        return generate_pdf_report_code(code, result, vulnerabilities)
    return render_template(
        "report_web_code_analysis.html",
        code=code,
        result=result,
        vulnerabilities=vulnerabilities,
        graphJSON=graphJSON,
        analysis_id=analysis_id,
        analysis=analysis  # ✅ هذا هو المطلوب
    )


@app.route('/delete_image_report/<int:analysis_id>', methods=['DELETE'])
@login_required
def delete_image_report(analysis_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'غير مصرح به'}), 403

    try:
        analysis = ImageAnalysis.query.get_or_404(analysis_id)
        db.session.delete(analysis)
        db.session.commit()
        return jsonify({'success': True, 'message': 'تم حذف التقرير بنجاح'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

def generate_pdf_report_code(code, result, vulnerabilities):
    pdf = FPDF()
    pdf.add_page()

    # إضافة محتوى التقرير
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="تقرير تحليل الثغرات الأمنية", ln=True, align='C')
    pdf.ln(10)

    # إضافة معلومات الثغرات
    pdf.cell(200, 10, txt="الثغرات المكتشفة:", ln=True)
    for vuln in vulnerabilities:
        pdf.cell(200, 10, txt=f"- {vuln['name']} ({vuln['severity']})", ln=True)
        pdf.multi_cell(0, 10, txt=f"الوصف: {vuln['description']}")
        pdf.multi_cell(0, 10, txt=f"الحل: {vuln['solution']}")
        pdf.ln(5)

    # إضافة نتائج النموذج
    if result and 'predictions' in result:
        pdf.cell(200, 10, txt="نتائج تحليل النموذج:", ln=True)
        for vuln, prob in result['predictions'].items():
            pdf.cell(0, 10, f"- {vuln}: {prob}%", ln=True)

    # إرجاع ملف PDF
    pdf_output = BytesIO()
    pdf.output(pdf_output)
    pdf_output.seek(0)
    return send_file(pdf_output, download_name="security_report.pdf", as_attachment=True)
def fix_stored_data(data):
    """إصلاح البيانات المخزنة كمصفوفة أحرف"""
    if isinstance(data, list):
        if all(isinstance(item, list) for item in data):
            # إذا كانت القائمة تحتوي على قوائم (مصفوفات أحرف)
            return [''.join(item) for item in data]
        elif all(isinstance(item, str) for item in data):
            # إذا كانت القائمة تحتوي على سلاسل نصية
            return data
    return data



if __name__ == '__main__':
    # استيراد وتسجيل مسارات تحليل الصور
    try:
        from image_analysis_routes import register_image_routes
        register_image_routes(app)
        print('✅ تم تسجيل مسارات تحليل الصور بنجاح')
    except Exception as e:
        print(f'❌ خطأ في تسجيل مسارات تحليل الصور: {str(e)}')

    # تشغيل التطبيق
    app.run(
        debug=app.config['DEBUG'],
        host=app.config['HOST'],
        port=app.config['PORT'])