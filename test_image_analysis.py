"""
ملف اختبار مستقل لوظائف تحليل الصور
يمكن تشغيل هذا الملف لاختبار وحدة تحليل الصور الجديدة
"""

import os
import json
import argparse
from win_image_analyzer import ImageAnalyzer
from datetime import datetime

def analyze_image(image_path, use_virustotal=False):
    """تحليل صورة باستخدام المحلل الجديد"""
    try:
        print(f"🔍 جاري تحليل الصورة: {image_path}")
        
        # التحقق من وجود الملف
        if not os.path.exists(image_path):
            print(f"❌ الملف غير موجود: {image_path}")
            return
            
        # تهيئة المحلل
        vt_api_key = '4f6a1d5109c67e49c1b3e32acd3bf5c89fa500f9db8d759d3fadb2e9da67c94e'
        analyzer = ImageAnalyzer(vt_api_key)
        
        # تحليل الصورة
        print("⏳ جاري التحليل...")
        start_time = datetime.now()
        result = analyzer.comprehensive_analysis(image_path, use_virustotal)
        end_time = datetime.now()
        analysis_time = (end_time - start_time).total_seconds()
        
        # عرض النتائج
        print("\n" + "="*60)
        print(f"📊 نتائج تحليل الصورة ({analysis_time:.2f} ثانية)")
        print("="*60)
        
        # معلومات أساسية
        print(f"📁 اسم الملف: {os.path.basename(image_path)}")
        print(f"📏 حجم الملف: {os.path.getsize(image_path):,} بايت")
        
        # نتيجة التحليل
        is_malicious = result.get('is_malicious', False)
        risk_score = result.get('risk_score', 0)
        
        if is_malicious:
            print(f"⚠️  النتيجة: خبيثة (درجة الخطورة: {risk_score:.1f}%)")
        else:
            print(f"✅ النتيجة: آمنة (درجة الخطورة: {risk_score:.1f}%)")
            
        # مؤشرات التهديد
        threat_indicators = result.get('threat_indicators', [])
        if threat_indicators:
            print(f"\n🚨 مؤشرات التهديد ({len(threat_indicators)}):")
            for indicator in threat_indicators:
                print(f"  • {indicator}")
        else:
            print("\n✅ لم يتم اكتشاف مؤشرات تهديد")
            
        # معلومات إضافية
        print("\n📋 معلومات إضافية:")
        file_signatures = result.get('file_signatures', {})
        if file_signatures:
            print(f"  • نوع الملف: {file_signatures.get('detected_format', 'غير معروف')}")
            
        steganography_detected = result.get('steganography_detected', False)
        print(f"  • إخفاء بيانات: {'نعم ✓' if steganography_detected else 'لا ✗'}")
        
        # حفظ النتائج في ملف JSON
        save_results = True
        if save_results:
            output_file = f"analysis_{os.path.basename(image_path)}.json"
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(result, f, ensure_ascii=False, indent=2)
            print(f"\n📄 تم حفظ النتائج المفصلة في: {output_file}")
            
    except Exception as e:
        print(f"❌ حدث خطأ أثناء تحليل الصورة: {str(e)}")

def main():
    """الدالة الرئيسية"""
    parser = argparse.ArgumentParser(description="تحليل الصور للكشف عن التهديدات")
    parser.add_argument("image_path", help="مسار الصورة للتحليل")
    parser.add_argument("--virustotal", action="store_true", help="استخدام VirusTotal للتحليل")
    
    args = parser.parse_args()
    analyze_image(args.image_path, args.virustotal)

if __name__ == "__main__":
    main()
