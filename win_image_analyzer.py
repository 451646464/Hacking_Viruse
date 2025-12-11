import os
import requests
import PIL.Image
import PIL.ExifTags
from urllib.parse import urlparse
import tempfile
import hashlib
import json
import logging
import time
from io import BytesIO
from datetime import datetime

# إعداد التسجيل
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ImageAnalyzer:
    def __init__(self, vt_api_key=None):
        self.vt_api_key = vt_api_key
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })

    def analyze_image_metadata(self, image_path):
        """تحليل البيانات الوصفية للصورة"""
        try:
            with PIL.Image.open(image_path) as img:
                metadata = {
                    'format': img.format,
                    'mode': img.mode,
                    'size': img.size,
                    'info': dict(img.info)
                }
                
                # استخراج بيانات EXIF
                exif_data = {}
                if hasattr(img, '_getexif') and img._getexif():
                    for tag, value in img._getexif().items():
                        tag_name = PIL.ExifTags.TAGS.get(tag, tag)
                        try:
                            # تحويل القيم إلى نصوص قابلة للتسلسل
                            if isinstance(value, (str, int, float, bool)):
                                exif_data[tag_name] = str(value)
                            elif isinstance(value, bytes):
                                try:
                                    exif_data[tag_name] = value.decode('utf-8', errors='ignore')
                                except:
                                    exif_data[tag_name] = 'Binary data'
                            else:
                                exif_data[tag_name] = str(value)
                        except Exception as ex:
                            exif_data[tag_name] = f'Unable to decode: {str(ex)}'
                
                metadata['exif'] = exif_data
                return metadata
                
        except Exception as e:
            logger.error(f"Error analyzing image metadata: {e}")
            return {'error': str(e)}

    def detect_steganography(self, image_path):
        """الكشف عن إخفاء البيانات في الصور"""
        try:
            with open(image_path, 'rb') as f:
                content = f.read()
            
            indicators = []
            
            # فحص أنماط مشبوهة في البيانات الثنائية
            suspicious_patterns = [
                b'<?php', b'eval(', b'base64_decode', b'gzinflate',
                b'cmd.exe', b'powershell', b'javascript:', b'<script',
                b'exec(', b'system(', b'shell_exec'
            ]
            
            for pattern in suspicious_patterns:
                if pattern in content:
                    try:
                        pattern_str = pattern.decode("utf-8", errors="ignore")
                        indicators.append(f'تم اكتشاف نمط مشبوه: {pattern_str}')
                    except:
                        indicators.append(f'تم اكتشاف نمط مشبوه: {pattern}')
            
            # فحص عدم تطابق توقيع الملف
            if content.startswith(b'\xFF\xD8\xFF'):  # JPEG
                if not content.endswith(b'\xFF\xD9'):
                    indicators.append('توقيع JPEG غير صحيح - قد يحتوي على بيانات إضافية')
            
            # فحص حجم البيانات المخفية المحتملة
            file_size = os.path.getsize(image_path)
            if file_size > 5 * 1024 * 1024:  # أكثر من 5MB
                indicators.append('حجم الملف كبير بشكل غير معتاد - قد يحتوي على بيانات مخفية')
            
            return indicators
            
        except Exception as e:
            logger.error(f"Error in steganography detection: {e}")
            return [f'خطأ في فحص الإستيجانوغرافي: {str(e)}']

    def analyze_file_signatures(self, image_path):
        """تحليل توقيعات الملفات"""
        signatures = {
            b'\xFF\xD8\xFF': 'JPEG',
            b'\x89PNG\r\n\x1a\n': 'PNG',
            b'GIF8': 'GIF',
            b'RIFF': 'WEBP',
            b'BM': 'BMP',
            b'II*\x00': 'TIFF',
            b'MM\x00*': 'TIFF'
        }
        
        try:
            with open(image_path, 'rb') as f:
                header = f.read(20)
            
            detected_format = None
            for sig, format_name in signatures.items():
                if header.startswith(sig):
                    detected_format = format_name
                    break
            
            # تحويل الرأس إلى تنسيق قابل للتسلسل
            header_ascii = ''.join(chr(b) if 32 <= b < 127 else '.' for b in header)
            
            return {
                'detected_format': detected_format,
                'header_hex': header.hex(),
                'header_ascii': header_ascii,
                'is_valid': detected_format is not None,
                'file_size': os.path.getsize(image_path)
            }
            
        except Exception as e:
            logger.error(f"Error analyzing file signatures: {e}")
            return {'error': str(e)}

    def scan_with_virustotal(self, file_path):
        """مسح الصورة باستخدام VirusTotal"""
        if not self.vt_api_key:
            return {'error': 'VirusTotal API key not configured'}
        
        try:
            # تحميل الملف إلى VirusTotal
            with open(file_path, 'rb') as file:
                upload_url = 'https://www.virustotal.com/vtapi/v2/file/scan'
                files = {'file': (os.path.basename(file_path), file)}
                params = {'apikey': self.vt_api_key}
                
                response = self.session.post(upload_url, files=files, params=params, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('response_code') == 1:
                    # انتظار معالجة الملف
                    time.sleep(15)
                    
                    report_url = 'https://www.virustotal.com/vtapi/v2/file/report'
                    report_params = {
                        'apikey': self.vt_api_key,
                        'resource': result['resource']
                    }
                    
                    report_response = self.session.get(report_url, params=report_params, timeout=30)
                    if report_response.status_code == 200:
                        report = report_response.json()
                        return {
                            'scan_id': result['resource'],
                            'permalink': report.get('permalink', ''),
                            'positives': report.get('positives', 0),
                            'total': report.get('total', 0),
                            'scans': report.get('scans', {}),
                            'scan_date': report.get('scan_date', ''),
                            'status': 'completed'
                        }
            
            return {'error': f'VirusTotal scan failed: {response.status_code}'}
                
        except Exception as e:
            logger.error(f"VirusTotal scan error: {e}")
            return {'error': f'VirusTotal error: {str(e)}'}

    def calculate_risk_score(self, metadata, steganography_indicators, file_signatures, vt_result=None):
        """حساب درجة خطورة الصورة"""
        risk_score = 0
        
        # مؤشرات البيانات الوصفية
        if metadata and not metadata.get('error'):
            exif = metadata.get('exif', {})
            suspicious_exif_fields = ['GPS', 'Coordinates', 'Software', 'Comment', 'XPComment']
            for field in suspicious_exif_fields:
                if any(field.lower() in key.lower() for key in exif.keys()):
                    risk_score += 15
            
            # فحص بيانات EXIF مشبوهة
            suspicious_values = ['photoshop', 'metadata', 'script', 'eval']
            for value in suspicious_values:
                if any(value in str(v).lower() for v in exif.values()):
                    risk_score += 10
        
        # مؤشرات الإستيجانوغرافي
        risk_score += len(steganography_indicators) * 25
        
        # مؤشرات توقيع الملف
        if file_signatures and not file_signatures.get('is_valid', True):
            risk_score += 30
        
        # نتائج VirusTotal
        if vt_result and not vt_result.get('error'):
            positives = vt_result.get('positives', 0)
            total = vt_result.get('total', 1)
            if positives > 0:
                vt_ratio = (positives / total) * 100
                risk_score = max(risk_score, vt_ratio)
        
        return min(risk_score, 100)

    def detect_suspicious_patterns(self, image_path):
        """الكشف عن الأنماط المشبوهة في الصورة"""
        patterns = []
        try:
            with open(image_path, 'rb') as f:
                content = f.read()
            
            # أنماط مشبوهة في المحتوى
            suspicious_strings = [
                b'cmd.exe', b'powershell', b'wscript.shell',
                b'regsvr32', b'certutil', b'bitsadmin',
                b'http://', b'https://', b'ftp://',
                b'base64', b'gzinflate', b'eval(',
                b'<script', b'javascript:', b'vbscript:'
            ]
            
            for pattern in suspicious_strings:
                if pattern in content:
                    try:
                        pattern_str = pattern.decode("utf-8", errors="ignore")
                        patterns.append(f'نمط مشبوه: {pattern_str}')
                    except:
                        patterns.append(f'نمط مشبوه: {pattern}')
            
            # فحص حجم الملف غير المعتاد
            file_size = os.path.getsize(image_path)
            if file_size > 10 * 1024 * 1024:  # أكثر من 10MB للصورة
                patterns.append('حجم الملف كبير بشكل غير معتاد للصورة')
            elif file_size < 100:  # أقل من 100 بايت
                patterns.append('حجم الملف صغير بشكل غير معتاد للصورة')
            
            return patterns
            
        except Exception as e:
            logger.error(f"Error detecting suspicious patterns: {e}")
            return [f'خطأ في كشف الأنماط: {str(e)}']

    def comprehensive_analysis(self, image_path, use_virustotal=False):
        """تحليل شامل للصورة"""
        try:
            logger.info(f"بدء التحليل الشامل للصورة: {image_path}")
            
            # التحقق من وجود الملف
            if not os.path.exists(image_path):
                return {
                    'is_malicious': False,
                    'prediction': 'فشل التحليل',
                    'probability': 0.0,
                    'risk_score': 0,
                    'error': 'الملف غير موجود'
                }
            
            # التحليلات الأساسية
            metadata = self.analyze_image_metadata(image_path)
            steganography_indicators = self.detect_steganography(image_path)
            file_signatures = self.analyze_file_signatures(image_path)
            suspicious_patterns = self.detect_suspicious_patterns(image_path)
            
            # فحص VirusTotal إذا كان مطلوباً
            vt_result = None
            if use_virustotal and self.vt_api_key:
                logger.info("بدء فحص VirusTotal...")
                vt_result = self.scan_with_virustotal(image_path)
            
            # حساب درجة الخطورة
            risk_score = self.calculate_risk_score(
                metadata, steganography_indicators, file_signatures, vt_result
            )
            
            # تحديد التصنيف النهائي
            is_malicious = risk_score >= 60
            prediction = "خبيثة" if is_malicious else "آمنة"
            
            # تجميع جميع مؤشرات التهديد
            all_threat_indicators = steganography_indicators + suspicious_patterns
            if vt_result and vt_result.get('positives', 0) > 0:
                all_threat_indicators.append(
                    f"تم اكتشاف {vt_result['positives']} من {vt_result['total']} محرك مضاد فيروسات"
                )
            
            result = {
                'is_malicious': is_malicious,
                'prediction': prediction,
                'probability': risk_score / 100,
                'risk_score': risk_score,
                'metadata': metadata,
                'steganography_detected': len(steganography_indicators) > 0,
                'steganography_indicators': steganography_indicators,
                'file_signatures': file_signatures,
                'suspicious_patterns': suspicious_patterns,
                'threat_indicators': all_threat_indicators,
                'virustotal_result': vt_result,
                'analysis_timestamp': str(datetime.now()),
                'file_hash': self.calculate_file_hash(image_path)
            }
            
            logger.info(f"اكتمل التحليل. النتيجة: {prediction}, درجة الخطورة: {risk_score}%")
            return result
            
        except Exception as e:
            logger.error(f"فشل التحليل الشامل: {e}")
            return {
                'is_malicious': False,
                'prediction': 'فشل التحليل',
                'probability': 0.0,
                'risk_score': 0,
                'error': str(e)
            }

    def download_image_from_url(self, image_url, save_path):
        """تحميل الصورة من الرابط"""
        try:
            response = self.session.get(image_url, timeout=30, stream=True)
            response.raise_for_status()
            
            with open(save_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            
            logger.info(f"تم تحميل الصورة بنجاح من: {image_url}")
            return True
            
        except Exception as e:
            logger.error(f"خطأ في تحميل الصورة من الرابط: {e}")
            return False

    def calculate_file_hash(self, file_path):
        """حساب بصمة الملف"""
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256()
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    file_hash.update(chunk)
            return file_hash.hexdigest()
        except Exception as e:
            logger.error(f"خطأ في حساب بصمة الملف: {e}")
            return None

    def generate_report(self, analysis_result, output_file=None):
        """إنشاء تقرير مفصل عن التحليل"""
        try:
            report = {
                'تحليل_الصورة': {
                    'التصنيف': analysis_result.get('prediction', 'غير معروف'),
                    'درجة_الخطورة': f"{analysis_result.get('risk_score', 0)}%",
                    'احتمالية_الخبث': f"{analysis_result.get('probability', 0) * 100:.2f}%",
                    'بصمة_الملف': analysis_result.get('file_hash', 'غير محسوبة'),
                    'تاريخ_التحليل': analysis_result.get('analysis_timestamp', 'غير معروف')
                },
                'البيانات_الوصفية': analysis_result.get('metadata', {}),
                'مؤشرات_التهديد': {
                    'اكتشاف_إخفاء_البيانات': analysis_result.get('steganography_detected', False),
                    'عدد_المؤشرات': len(analysis_result.get('threat_indicators', [])),
                    'التفاصيل': analysis_result.get('threat_indicators', [])
                },
                'توقيعات_الملف': analysis_result.get('file_signatures', {}),
                'نتائج_VirusTotal': analysis_result.get('virustotal_result', {})
            }
            
            if output_file:
                try:
                    with open(output_file, 'w', encoding='utf-8') as f:
                        json.dump(report, f, ensure_ascii=False, indent=4)
                    logger.info(f"تم حفظ التقرير في: {output_file}")
                    return True
                except Exception as e:
                    logger.error(f"خطأ في حفظ التقرير: {e}")
                    return False
            
            return report
            
        except Exception as e:
            logger.error(f"خطأ في إنشاء التقرير: {e}")
            return {'error': str(e)}


# دالة مساعدة للاستخدام المباشر
def analyze_image(image_path, vt_api_key=None, use_vt=False):
    """
    دالة مساعدة لتحليل صورة بسهولة
    
    الوسائط:
        image_path: مسار الصورة
        vt_api_key: مفتاح VirusTotal (اختياري)
        use_vt: استخدام VirusTotal (افتراضي: False)
    
    الإرجاع:
        نتيجة التحليل
    """
    analyzer = ImageAnalyzer(vt_api_key=vt_api_key)
    return analyzer.comprehensive_analysis(image_path, use_virustotal=use_vt)
