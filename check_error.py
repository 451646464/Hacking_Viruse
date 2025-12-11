from app import app
from models import ImageAnalysis

def test_image_report_access():
    with app.app_context():
        # الحصول على آخر سجل تحليل صورة
        analysis = ImageAnalysis.query.order_by(ImageAnalysis.id.desc()).first()
        if not analysis:
            print("لا توجد تحليلات للصور في قاعدة البيانات")
            return
            
        # اختبار للوصول إلى metadata_analysis
        try:
            test = analysis.metadata_analysis
            print(f"metadata_analysis: {test}")
        except Exception as e:
            print(f"Error accessing metadata_analysis: {type(e).__name__}: {str(e)}")
            
        # اختبار الوصول إلى file_signatures
        try:
            test = analysis.file_signatures
            print(f"file_signatures: {test}")
        except Exception as e:
            print(f"Error accessing file_signatures: {type(e).__name__}: {str(e)}")
            
        # اختبار الوصول إلى نتائج التحليل
        try:
            results = analysis.get_analysis_results()
            print(f"analysis_results accessible: {bool(results)}")
        except Exception as e:
            print(f"Error accessing analysis_results: {type(e).__name__}: {str(e)}")

if __name__ == "__main__":
    test_image_report_access()
