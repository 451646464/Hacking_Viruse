"""
ملف تحديث لتطبيق Flask
لتسجيل مسارات تحليل الصور الجديدة
"""

# إضافة هذا الكود في نهاية ملف app.py:

# استيراد مسارات تحليل الصور الجديدة
from image_analysis_routes import register_image_routes

# تسجيل مسارات تحليل الصور
register_image_routes(app)

print("✅ تم تسجيل مسارات تحليل الصور بنجاح")
