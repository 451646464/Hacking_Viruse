"""
ملف مسارات تحليل الصور الجديد
يحتوي على جميع المسارات والدوال الخاصة بتحليل الصور باستخدام المحلل الجديد
"""

import os
import json
import hashlib
import secrets
import tempfile
from io import BytesIO
from datetime import datetime, timedelta
from urllib.parse import urlparse

from flask import render_template, request, flash, redirect, url_for, abort, send_file, jsonify
from flask_login import login_required, current_user

from models import ImageAnalysis, db
from image_analyzer import ImageAnalyzer  # استخدام المحلل الأصلي - يمكن استبداله بـ image_analyzer_new إذا لزم الأمر
from utils import safe_delete

# التكوين
ALLOWED_EXTENSIONS_IMAGE = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'tiff'}

# فحص امتداد الملف
def allowed_file_image(filename):
    """التحقق من أن الملف من ضمن الأنواع المسموحة"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS_IMAGE

def register_image_routes(app):
    """
    تسجيل مسارات تحليل الصور في تطبيق Flask
    
    المسارات المتاحة:
        - /image_analysis (موجودة بالفعل في app.py)
        - /analyze_image (تحويل للمسار الرئيسي)
        - /analysis_image (تحويل للمسار الرئيسي)
        - /image_report/<id>
        - /share_image_analysis/<id>
        - /shared/image/<token>
        - /generate_image_pdf/<id>
        - /delete_image_analysis/<id>
    """
    
    # تحويل من المسار القديم (analyze_image) إلى المسار الجديد
    @app.route('/analyze_image', methods=['GET', 'POST'])
    @login_required
    def analyze_image():
        """تحويل من المسار القديم إلى الجديد"""
        return redirect(url_for('image_analysis'))
        
    # تحويل من المسار المتوسط (analysis_image) إلى المسار الجديد
    @app.route('/analysis_image', methods=['GET', 'POST'])
    @login_required
    def analysis_image():
        """تحويل من المسار المتوسط إلى الجديد"""
        return redirect(url_for('image_analysis'))
        
    # صفحة التقرير - معطلة لمنع التعارض مع app.py
    # @app.route('/image_report/<int:analysis_id>')
    # @login_required
    # def image_report(analysis_id):
    #     """عرض تقرير تحليل الصورة"""
    #     try:
    #         analysis = ImageAnalysis.query.get_or_404(analysis_id)
    #         
    #         if analysis.user_id != current_user.id and not current_user.is_admin:
    #             flash('غير مصرح لك بالوصول إلى هذا التقرير', 'danger')
    #             return redirect(url_for('image_analysis'))
    #         
    #         # استخراج البيانات من نتائج التحليل
    #         results = analysis.get_analysis_results()
    #         metadata = results.get('metadata', {})
    #         file_signatures = results.get('file_signatures', {})
    #         
    #         app.logger.info(f"عرض تقرير تحليل الصورة - ID: {analysis_id}")
    #         
    #         return render_template(
    #             'image_report.html',
    #             analysis=analysis,
    #             metadata=metadata,
    #             file_signatures=file_signatures,
    #             json=json  # تمرير وحدة json إلى القالب
    #         )
    #     except Exception as e:
    #         app.logger.error(f"خطأ في تحميل التقرير: {str(e)}")
    #         flash(f'خطأ في تحميل التقرير: {str(e)}', 'error')
    #         return redirect(url_for('image_analysis'))
    
    return True  # لتأكيد نجاح التسجيل
