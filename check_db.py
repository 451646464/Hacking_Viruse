from app import app
from database import db
import json

def print_table_structure(table_name):
    """طباعة هيكل الجدول في قاعدة البيانات"""
    with app.app_context():
        # جلب معلومات الجدول
        inspector = db.inspect(db.engine)
        columns = inspector.get_columns(table_name)
        
        print(f"\n==== هيكل جدول '{table_name}' ====")
        for column in columns:
            print(f"- {column['name']} ({column['type']})")

def check_image_analysis_record(record_id):
    """التحقق من سجل تحليل الصورة المحدد"""
    from models import ImageAnalysis
    
    with app.app_context():
        record = ImageAnalysis.query.get(record_id)
        if not record:
            print(f"لم يتم العثور على السجل بالمعرف: {record_id}")
            return
        
        print(f"\n==== سجل تحليل الصورة {record_id} ====")
        print(f"- filename: {record.filename}")
        print(f"- file_hash: {record.file_hash}")
        print(f"- is_malicious: {record.is_malicious}")
        print(f"- threat_score: {record.threat_score}")
        
        # التحقق من وجود الحقول الإضافية
        print(f"\n-- الحقول التي تمت إضافتها --")
        print(f"- threat_indicators: {hasattr(record, 'threat_indicators')}")
        print(f"- virustotal_result: {hasattr(record, 'virustotal_result')}")
        print(f"- virustotal_scan_date: {hasattr(record, 'virustotal_scan_date')}")
        print(f"- share_token: {hasattr(record, 'share_token')}")
        print(f"- share_expiry: {hasattr(record, 'share_expiry')}")
        
        # التحقق من وجود الحقول القديمة
        print(f"\n-- الحقول القديمة --")
        print(f"- metadata_analysis: {hasattr(record, 'metadata_analysis')}")
        print(f"- file_signatures: {hasattr(record, 'file_signatures')}")
        print(f"- prediction: {hasattr(record, 'prediction')}")
        print(f"- risk_score: {hasattr(record, 'risk_score')}")
        
        # طباعة محتوى analysis_results
        try:
            results = record.get_analysis_results()
            print(f"\n-- محتوى analysis_results --")
            print(json.dumps(results, ensure_ascii=False, indent=2))
        except Exception as e:
            print(f"خطأ في قراءة analysis_results: {str(e)}")

if __name__ == "__main__":
    print_table_structure('image_analyses')
    
    # التحقق من أحدث سجل
    from models import ImageAnalysis
    with app.app_context():
        latest_record = ImageAnalysis.query.order_by(ImageAnalysis.id.desc()).first()
        if latest_record:
            check_image_analysis_record(latest_record.id)
