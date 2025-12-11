from datetime import datetime
from flask_login import UserMixin
from database import db
import json


class User(UserMixin, db.Model):
    __tablename__ = 'users'  # تحديد اسم الجدول بشكل صريح

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=True)
    profile_image = db.Column(db.String(255))
    is_admin = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    api_key = db.Column(db.String(64), nullable=True)

    # العلاقات
    oauth = db.relationship('OAuth', back_populates='user', lazy=True)

    def update_last_login(self):
        self.last_login = datetime.utcnow()
        db.session.commit()


class OAuth(db.Model):
    __tablename__ = 'oauth'

    id = db.Column(db.Integer, primary_key=True)
    provider = db.Column(db.String(50), nullable=False)
    provider_user_id = db.Column(db.String(256), nullable=False)
    token = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # تصحيح هنا
    user = db.relationship('User', back_populates='oauth')


class UserSettings(db.Model):
    __tablename__ = 'user_settings'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True, nullable=False)
    language = db.Column(db.String(10), default='ar')
    time_format = db.Column(db.String(10), default='24')
    theme = db.Column(db.String(10), default='dark')
    email_notifications = db.Column(db.Boolean, default=True)
    security_notifications = db.Column(db.Boolean, default=True)
    app_notifications = db.Column(db.Boolean, default=True)
    newsletter = db.Column(db.Boolean, default=False)
    private_account = db.Column(db.Boolean, default=False)
    secure_login = db.Column(db.Boolean, default=True)
    analytics = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('settings', uselist=False))


class ImageAnalysis(db.Model):
    __tablename__ = 'image_analyses'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    file_hash = db.Column(db.String(64), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    analysis_date = db.Column(db.DateTime, default=datetime.utcnow)
    
    # نتائج التحليل
    is_malicious = db.Column(db.Boolean, nullable=True, default=False)
    prediction = db.Column(db.String(50), nullable=True, default='غير معروف')
    probability = db.Column(db.Float, default=0.0)
    
    # تحليلات متقدمة
    metadata_analysis = db.Column(db.Text)
    exif_data = db.Column(db.Text)
    steganography_detected = db.Column(db.Boolean, default=False)
    hidden_content = db.Column(db.Text)
    suspicious_patterns = db.Column(db.Text)
    file_signatures = db.Column(db.Text)
    
    # VirusTotal Integration
    virustotal_result = db.Column(db.Text)
    virustotal_scan_date = db.Column(db.DateTime)
    
    # مؤشرات الخطر
    risk_score = db.Column(db.Integer)
    threat_indicators = db.Column(db.Text)
    threat_type = db.Column(db.String(100))  # مثل: "Phishing", "Malicious", "Injected", etc.
    
    # معلومات المشاركة
    share_token = db.Column(db.String(32), unique=True)
    share_expiry = db.Column(db.DateTime)
    
    user = db.relationship('User', backref=db.backref('image_analyses', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'file_size': self.file_size,
            'is_malicious': self.is_malicious,
            'prediction': self.prediction,
            'probability': self.probability,
            'upload_date': self.upload_date,
            'risk_score': self.risk_score
        }
    
    def get_analysis_results(self):
        """استرجاع نتائج التحليل المخزنة"""
        try:
            # تجميع كل النتائج في قاموس واحد
            results = {
                'prediction': self.prediction,
                'probability': self.probability,
                'risk_score': self.risk_score,
                'steganography_detected': self.steganography_detected,
            }
            
            # إضافة البيانات الإضافية إذا كانت موجودة
            if self.metadata_analysis:
                results['metadata'] = json.loads(self.metadata_analysis) if isinstance(self.metadata_analysis, str) else self.metadata_analysis
            
            if self.suspicious_patterns:
                results['suspicious_patterns'] = json.loads(self.suspicious_patterns) if isinstance(self.suspicious_patterns, str) else self.suspicious_patterns
                
            if self.file_signatures:
                results['file_signatures'] = json.loads(self.file_signatures) if isinstance(self.file_signatures, str) else self.file_signatures
                
            if self.hidden_content:
                results['steganography_indicators'] = json.loads(self.hidden_content) if isinstance(self.hidden_content, str) else self.hidden_content
            
            return results
        except Exception as e:
            return {"error": f"فشل في استرجاع نتائج التحليل: {str(e)}"}
    
    def set_analysis_results(self, results_dict):
        """تخزين نتائج التحليل في الحقول المناسبة"""
        try:
            # تخزين البيانات الرئيسية
            self.prediction = results_dict.get('prediction', 'غير معروف')
            self.probability = results_dict.get('probability', 0.0)
            self.risk_score = results_dict.get('risk_score', 0)
            self.steganography_detected = results_dict.get('steganography_detected', False)
            
            # تخزين البيانات المفصلة
            if 'metadata' in results_dict:
                self.metadata_analysis = json.dumps(results_dict['metadata'], ensure_ascii=False)
                
            if 'suspicious_patterns' in results_dict:
                self.suspicious_patterns = json.dumps(results_dict['suspicious_patterns'], ensure_ascii=False)
                
            if 'file_signatures' in results_dict:
                self.file_signatures = json.dumps(results_dict['file_signatures'], ensure_ascii=False)
                
            if 'steganography_indicators' in results_dict:
                self.hidden_content = json.dumps(results_dict['steganography_indicators'], ensure_ascii=False)
                
        except Exception as e:
            import logging
            logging.error(f"خطأ في تخزين نتائج التحليل: {str(e)}")

    def get_threat_indicators(self):
        return json.loads(self.threat_indicators) if self.threat_indicators else []
    
    def set_threat_indicators(self, indicators):
        self.threat_indicators = json.dumps(indicators, ensure_ascii=False)
    
    def get_virustotal_result(self):
        return json.loads(self.virustotal_result) if self.virustotal_result else {}
    
    def set_virustotal_result(self, vt_result):
        self.virustotal_result = json.dumps(vt_result, ensure_ascii=False)

class PDFAnalysis(db.Model):
    __tablename__ = 'pdf_analyses'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # تصحيح هنا
    filename = db.Column(db.String(255), nullable=False)
    file_hash = db.Column(db.String(64), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)
    results = db.Column(db.Text, nullable=False)
    is_malicious = db.Column(db.Boolean, default=False)
    threat_score = db.Column(db.Float, default=0.0)
    engines_used = db.Column(db.Text)
    engines_total = db.Column(db.Integer, default=0)
    engines_detected = db.Column(db.Integer, default=0)
    vulnerabilities = db.Column(db.Text)
    file_metadata = db.Column(db.Text)

    user = db.relationship('User', backref=db.backref('pdf_analyses', lazy=True))

    def set_results(self, results_dict):
        self.results = json.dumps(results_dict)

    def get_results(self):
        return json.loads(self.results) if self.results else {}

    def set_engines_used(self, engines_list):
        self.engines_used = json.dumps(engines_list)

    def get_engines_used(self):
        return json.loads(self.engines_used) if self.engines_used else []

    def set_vulnerabilities(self, vulnerabilities_list):
        self.vulnerabilities = json.dumps(vulnerabilities_list)

    def get_vulnerabilities(self):
        return json.loads(self.vulnerabilities) if self.vulnerabilities else []

    def set_file_metadata(self, metadata_dict):
        self.file_metadata = json.dumps(metadata_dict)

    def get_file_metadata(self):
        return json.loads(self.file_metadata) if self.file_metadata else {}


class CodeAnalysis(db.Model):
    __tablename__ = 'code_analyses'

    id = db.Column(db.Integer, primary_key=True)
    analysis_type = db.Column(db.String(50), nullable=False)
    content = db.Column(db.Text, nullable=False)
    analysis_date = db.Column(db.DateTime, default=datetime.utcnow)
    vulnerabilities = db.Column(db.Text)
    model_predictions = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))  # تصحيح هنا

    def set_vulnerabilities(self, vuln_list):
        self.vulnerabilities = json.dumps(vuln_list, ensure_ascii=False)

    def get_vulnerabilities(self):
        return json.loads(self.vulnerabilities) if self.vulnerabilities else []

    def set_model_predictions(self, predictions):
        self.model_predictions = json.dumps(predictions, ensure_ascii=False)

    def get_model_predictions(self):
        return json.loads(self.model_predictions) if self.model_predictions else {}


class URLAnalysis(db.Model):
    __tablename__ = 'url_analyses'

    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)
    is_malicious = db.Column(db.Boolean)
    ssl_status = db.Column(db.String(200))
    model_prediction = db.Column(db.String(50))
    content_analysis = db.Column(db.String(200))
    html_analysis = db.Column(db.String(200))
    javascript_analysis = db.Column(db.String(200))
    virustotal_result = db.Column(db.Text)
    final_result = db.Column(db.String(200))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))  # تصحيح هنا

    def to_dict(self):
        # تحديد ما إذا كان الرابط آمناً بناءً على final_result
        is_safe = "Legitimate" in self.final_result or "Safe" in self.final_result or "آمن" in self.final_result
        is_malicious = "Phishing" in self.final_result or "مشبوه" in self.final_result
        
        return {
            "url": self.url,
            "ssl": {"status": "صالح" in self.ssl_status or "valid" in self.ssl_status.lower() if self.ssl_status else False, 
                    "message": self.ssl_status},
            "model": {"prediction": 1 if "Legitimate" in str(self.model_prediction) else -1,
                      "label": self.model_prediction},
            "content": {"status": "لا توجد" in self.content_analysis or "no suspicious" in self.content_analysis.lower() if self.content_analysis else True,
                        "message": self.content_analysis},
            "html": {"status": "طبيعي" in self.html_analysis or "normal" in self.html_analysis.lower() if self.html_analysis else True,
                     "message": self.html_analysis},
            "javascript": {"status": "لا توجد" in self.javascript_analysis or "no suspicious" in self.javascript_analysis.lower() if self.javascript_analysis else True,
                           "message": self.javascript_analysis},
            "vt": {"status": not is_malicious if self.virustotal_result else None,
                   "message": self.virustotal_result},
            "final": {"status": is_safe and not is_malicious,
                      "message": self.final_result}
        }


class WebAnalysis(db.Model):
    __tablename__ = 'web_analyses'

    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)
    scan_type = db.Column(db.String(50), nullable=False)
    total_links = db.Column(db.Integer)
    vulnerable_links = db.Column(db.Integer)
    vulnerabilities = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))  # تصحيح هنا
    user = db.relationship('User', backref=db.backref('web_analyses', lazy=True))

    def set_vulnerabilities(self, vuln_data):
        def convert_bools(obj):
            if isinstance(obj, bool):
                return str(obj)
            elif isinstance(obj, dict):
                return {k: convert_bools(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_bools(item) for item in obj]
            return obj

        try:
            self.vulnerabilities = json.dumps(convert_bools(vuln_data), ensure_ascii=False)
        except Exception as e:
            self.vulnerabilities = json.dumps({"error": str(e)})

    def get_vulnerabilities(self):
        return json.loads(self.vulnerabilities) if self.vulnerabilities else []


class AnalysisSample(db.Model):
    __tablename__ = 'analysis_samples'

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    file_hash = db.Column(db.String(64), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    prediction = db.Column(db.String(50), nullable=False)
    probability = db.Column(db.Float, nullable=False)
    is_malicious = db.Column(db.Boolean, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))  # تصحيح هنا
    user = db.relationship('User', backref=db.backref('samples', lazy=True))

    # نتائج التحليل
    header_info = db.Column(db.Text)
    sections_info = db.Column(db.Text)
    imports_info = db.Column(db.Text)
    dynamic_indicators = db.Column(db.Text)
    sandbox_report = db.Column(db.Text)

    # الحقول الجديدة
    strings = db.Column(db.Text)
    binwalk_results = db.Column(db.Text)
    entropy = db.Column(db.Float)
    packed = db.Column(db.Boolean)
    network_indicators = db.Column(db.Text)
    yara_matches = db.Column(db.Text)
    libraries = db.Column(db.Text)
    powershell_commands = db.Column(db.Text)
    persistence_indicators = db.Column(db.Text)
    c2_indicators = db.Column(db.Text)
    mitre_techniques = db.Column(db.Text)

    # معلومات المشاركة
    share_token = db.Column(db.String(32), unique=True)
    share_expiry = db.Column(db.DateTime)

    # الحقول الأخرى
    network_activity = db.Column(db.Text)
    file_activity = db.Column(db.Text)
    process_tree = db.Column(db.Text)
    strings_info = db.Column(db.Text)

    def __repr__(self):
        return f'<AnalysisSample {self.filename}>'


class Notification(db.Model):
    """نموذج الإشعارات للمستخدمين"""
    __tablename__ = 'notifications'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    title = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    notification_type = db.Column(db.String(50), default='general')  # general, security, system, admin
    icon = db.Column(db.String(50), default='bell')  # fa icon name: bell, shield, lock, etc.
    link = db.Column(db.String(255), nullable=True)  # رابط لتوجيه المستخدم عند النقر على الإشعار
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    is_global = db.Column(db.Boolean, default=False)  # إشعارات عامة لجميع المستخدمين
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # المستخدم الذي أرسل الإشعار (المدير)
    
    # العلاقات
    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('received_notifications', lazy=True))
    sender = db.relationship('User', foreign_keys=[sender_id], backref=db.backref('sent_notifications', lazy=True))
    
    def __repr__(self):
        return f'<Notification {self.id} for user {self.user_id}: {self.title}>'
    
    def to_dict(self):
        """تحويل الإشعار إلى قاموس للعرض في واجهة المستخدم"""
        return {
            'id': self.id,
            'title': self.title,
            'message': self.message,
            'type': self.notification_type,
            'icon': self.icon,
            'link': self.link,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'is_read': self.is_read,
            'is_global': self.is_global,
            'sender_id': self.sender_id
        }