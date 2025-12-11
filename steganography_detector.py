"""
وحدة متخصصة للكشف عن البيانات المخفية والمحقونة في الصور
"""
import os
import struct
import binascii
import re
import numpy as np
from PIL import Image
import io
import zipfile
import tarfile

class SteganographyDetector:
    """فئة متخصصة في الكشف عن البيانات المخفية في الصور باستخدام طرق مختلفة"""

    def __init__(self):
        self.results = {}
        # قائمة برؤوس الملفات الشائعة
        self.file_signatures = {
            b'PK\x03\x04': 'ZIP archive (zip)',
            b'PK\x05\x06': 'ZIP archive empty (zip)',
            b'PK\x07\x08': 'ZIP archive spanned (zip)',
            b'\x1F\x8B\x08': 'GZIP archive (gz)',
            b'\x42\x5A\x68': 'BZIP2 archive (bz2)',
            b'\x75\x73\x74\x61\x72': 'TAR archive (tar)',
            b'\x52\x61\x72\x21\x1A\x07': 'RAR archive (rar)',
            b'\x7F\x45\x4C\x46': 'ELF executable (elf)',
            b'\x4D\x5A': 'DOS/PE executable (exe)',
            b'\x7F\x45\x4C\x46': 'ELF executable (elf)',
            b'\xFF\xD8\xFF': 'JPEG image (jpg)',
            b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A': 'PNG image (png)',
            b'\x47\x49\x46\x38': 'GIF image (gif)',
            b'\x3C\x3F\x70\x68\x70': 'PHP script (php)',
            b'\x3C\x3F\x78\x6D\x6C': 'XML file (xml)',
            b'\x3C\x68\x74\x6D\x6C': 'HTML file (html)',
            b'\x3C\x21\x44\x4F\x43': 'HTML document (html)',
            b'\x25\x50\x44\x46': 'PDF document (pdf)',
            b'\xD0\xCF\x11\xE0': 'MS Office document (doc/xls)',
            b'\x50\x4B\x03\x04\x14\x00\x06\x00': 'MS Office 2007+ document (docx/xlsx/pptx)',
            b'\x23\x21': 'Shell script (sh)',
            b'\x69\x6D\x70\x6F\x72\x74': 'Python script (py)',
            b'\x63\x6C\x61\x73\x73': 'Java class file (class)',
            b'\x75\x73\x65\x20\x73': 'Perl script (pl)',
            b'\x52\x49\x46\x46': 'RIFF container (avi/wav)',
            b'\x66\x4C\x61\x43': 'FLAC audio (flac)',
        }
        
        # أنماط أكواد مشبوهة
        self.suspicious_patterns = [
            # أكواد PHP
            br'<\?php',
            br'system\s*\(',
            br'shell_exec\s*\(',
            br'exec\s*\(',
            br'passthru\s*\(',
            br'eval\s*\(',
            
            # أكواد JavaScript
            br'<script',
            br'eval\s*\(',
            br'document\.write',
            br'fromCharCode',
            br'String\.fromCharCode',
            
            # أكواد HTML
            br'<iframe',
            br'<img[^>]+onerror',
            
            # باي لود مشفرة
            br'base64_decode',
            br'atob\s*\(',
            br'btoa\s*\(',
            
            # أنماط URL
            br'https?:\/\/',
            br'ftp:\/\/',
            
            # أكواد هجمات
            br'uname -a',
            br'\/etc\/passwd',
            br'\/bin\/bash',
            br'cmd\.exe',
            br'powershell',
            
            # أنماط IP
            br'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
            
            # أنماط متنوعة
            br'backdoor',
            br'rootkit',
            br'exploit',
            br'hack',
            
            # أنماط تشفير وتعمية
            br'AES',
            br'Rijndael',
            br'XOR',
            br'0x[0-9a-fA-F]+'
        ]
        
    def analyze_image(self, image_path):
        """تحليل الصورة باستخدام عدة طرق للكشف عن البيانات المخفية"""
        self.results = {
            'embedded_files': [],
            'suspicious_code': [],
            'hidden_text': [],
            'metadata_anomalies': [],
            'pixel_anomalies': [],
            'lsb_analysis': {},
            'risk_score': 0,
            'detected_threats': []
        }
        
        # قراءة الملف كبيانات ثنائية
        try:
            with open(image_path, 'rb') as f:
                file_data = f.read()
                
            # 1. البحث عن أنماط رؤوس الملفات المعروفة 
            self._search_file_headers(file_data)
            
            # 2. البحث عن أنماط الأكواد المشبوهة
            self._search_suspicious_patterns(file_data)
            
            # 3. تحليل بيانات ما بعد نهاية الصورة
            self._check_data_after_eof(image_path, file_data)
            
            # 4. تحليل البيانات المخفية باستخدام LSB
            self._analyze_lsb_steganography(image_path)
            
            # 5. البحث عن تغييرات في تشبع الألوان
            self._analyze_color_saturation(image_path)
            
            # 6. تحليل المنطقة غير المرئية من الصورة
            self._check_invisible_areas(image_path)
            
            # 7. فحص قابلية استخراج ملفات مضغوطة
            self._check_embedded_archives(file_data)
            
            # 8. حساب درجة الخطورة
            self._calculate_risk_score()
            
            return self.results
            
        except Exception as e:
            self.results['error'] = str(e)
            return self.results
    
    def _search_file_headers(self, file_data):
        """البحث عن رؤوس الملفات المعروفة داخل الملف"""
        for signature, file_type in self.file_signatures.items():
            # تجاهل مطابقة رؤوس الملفات في بداية الصورة (تجنب الإيجابيات الخاطئة)
            # البحث بعد البايت 100 
            start_index = 100
            
            # البحث عن التوقيعات في جميع أنحاء الملف
            offset = file_data.find(signature, start_index)
            
            # إذا تم العثور على توقيع
            if offset != -1:
                # فحص المنطقة المحيطة بالتوقيع للتأكد من أنه ليس جزءًا طبيعيًا من الصورة
                # هذا يساعد في تقليل الإيجابيات الخاطئة
                context = file_data[max(0, offset-10):offset+len(signature)+10]
                
                # إذا كان التوقيع ضمن بيانات مشبوهة
                if not self._is_false_positive(signature, offset, context):
                    self.results['embedded_files'].append({
                        'type': file_type,
                        'offset': offset,
                        'signature': binascii.hexlify(signature).decode('ascii')
                    })
                    
                    # إضافة التهديد المكتشف
                    threat_name = f"Embedded {file_type.split(' ')[0]} detected"
                    if threat_name not in self.results['detected_threats']:
                        self.results['detected_threats'].append(threat_name)
    
    def _is_false_positive(self, signature, offset, context):
        """فحص ما إذا كان توقيع الملف إيجابي خاطئ (جزء طبيعي من الصورة)"""
        # بعض التوقيعات تظهر بشكل طبيعي في الصور
        # إذا كان التوقيع في بداية الملف، فقد يكون توقيع الصورة نفسها
        if offset < 200:
            # تجاهل التوقيعات في منطقة رأس الصورة
            return True
        
        # فحص المنطقة المحيطة بالتوقيع للتأكد من سياقه
        # مثلاً، إذا كانت البيانات حوله متشابهة/متكررة، قد يكون جزءًا طبيعيًا من الصورة
        bytes_before = context[:10]
        bytes_after = context[-10:]
        
        # تحقق من توحيد البيانات المحيطة - مؤشر على البيانات المتسلسلة الطبيعية
        if len(set(bytes_before)) < 3 or len(set(bytes_after)) < 3:
            return True
        
        # توقيعات آمنة غالباً ما تكون موجودة في الصور بشكل طبيعي
        safe_signatures = [b'JFIF', b'Exif', b'ICC_PROFILE', b'XMP', b'<?xml']
        for safe_sig in safe_signatures:
            if safe_sig in context:
                return True
                
        # الآن نتحقق من التوقيعات الخطيرة المعروفة
        dangerous_signatures = [
            b'\x4D\x5A',  # DOS/PE executable
            b'\x3C\x3F\x70\x68\x70',  # PHP
            b'\x23\x21',  # Shell script
            b'\x7F\x45\x4C\x46'  # ELF executable
        ]
        
        # إذا كان التوقيع من التوقيعات الخطيرة، نحتاج تأكيد إضافي
        for ds in dangerous_signatures:
            if signature.startswith(ds):
                # تحقق من وجود سلاسل نصية مرتبطة بالتنفيذ حول التوقيع
                exec_markers = [b'exec', b'system', b'cmd', b'powershell', b'/bin/sh']
                for marker in exec_markers:
                    if marker in context:
                        # تأكيد إضافي أن هذا توقيع خطير حقيقي
                        return False
                
                # تحقق من طول التوقيع المحتمل - التوقيعات الحقيقية عادةً أطول
                # حساب الطول من التوقيع حتى نهاية البيانات أو بايتات خاصة
                chunk_size = 50
                if offset + chunk_size < len(self.file_data):
                    chunk = self.file_data[offset:offset+chunk_size]
                    # تحقق من وجود بيانات ثنائية ذات معنى
                    if sum(c < 32 or c > 126 for c in chunk) > chunk_size * 0.7:
                        # يبدو كملف ثنائي حقيقي
                        return False
        
        # التوقيعات المعروفة بالإيجابيات الكاذبة
        false_positive_signatures = [b'http://', b'https://', b'0x0', b'0x1', b'0x2', b'0x3', b'0x4', b'0x5']
        for fp_sig in false_positive_signatures:
            if signature == fp_sig:
                return True
        
        # افتراضيًا، نعتبر التوقيع مشبوهًا
        return False
    
    def _search_suspicious_patterns(self, file_data):
        """البحث عن أنماط الأكواد المشبوهة"""
        self.file_data = file_data  # تخزين الملف للاستخدام في _is_false_positive
        
        # قائمة الأنماط التي تسبب إيجابيات كاذبة بشكل متكرر
        common_false_positives = [
            br'https?:\/\/',  # URLs شائعة
            br'0x[0-9a-fA-F]+',  # قيم سداسية عادية
            br'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'  # أرقام IP
        ]
        
        # الأنماط عالية الخطورة التي نخصص لها اهتمامًا خاصًا
        high_risk_patterns = [
            br'<\?php',
            br'system\s*\(',
            br'shell_exec\s*\(',
            br'exec\s*\(',
            br'passthru\s*\(',
            br'eval\s*\(',
            br'<script',
            br'cmd\.exe',
            br'powershell',
            br'\/bin\/bash'
        ]
        
        # البحث عن الأنماط عالية الخطورة أولاً
        for pattern in high_risk_patterns:
            matches = re.finditer(pattern, file_data)
            for match in matches:
                offset = match.start()
                matched_text = match.group()
                
                # تجاهل المطابقات في البيانات الوصفية (الـ 200 بايت الأولى)
                if offset > 200:  
                    try:
                        text = matched_text.decode('utf-8', errors='replace')
                    except:
                        text = str(matched_text)
                    
                    # استخراج سياق موسع للمطابقة للتأكد من دقة الكشف
                    context_start = max(0, offset - 20)
                    context_end = min(len(file_data), offset + len(matched_text) + 20)
                    context = file_data[context_start:context_end]
                    
                    # التحقق من وجود مؤشرات إضافية للخطر
                    if self._validate_code_threat(pattern, context, offset):
                        self.results['suspicious_code'].append({
                            'pattern': text,
                            'offset': offset,
                            'context': binascii.hexlify(context).decode('ascii'),
                            'severity': 'high'
                        })
                        
                        # إضافة التهديد المكتشف
                        threat_name = "Suspicious code pattern detected"
                        if threat_name not in self.results['detected_threats']:
                            self.results['detected_threats'].append(threat_name)
        
        # البحث عن الأنماط الأخرى بعد استبعاد الإيجابيات الكاذبة الشائعة
        for pattern in self.suspicious_patterns:
            # تجاهل الأنماط عالية الخطورة (تم التحقق منها مسبقًا)
            if pattern in high_risk_patterns:
                continue
                
            # تجاهل الإيجابيات الكاذبة الشائعة
            if pattern in common_false_positives:
                continue
                
            matches = re.finditer(pattern, file_data)
            for match in matches:
                offset = match.start()
                matched_text = match.group()
                
                # تجاهل المطابقات في البيانات الوصفية ورأس الصورة
                if offset > 1000:  
                    try:
                        text = matched_text.decode('utf-8', errors='replace')
                    except:
                        text = str(matched_text)
                    
                    # استخراج سياق المطابقة
                    context_start = max(0, offset - 10)
                    context_end = min(len(file_data), offset + len(matched_text) + 10)
                    context = file_data[context_start:context_end]
                    
                    # التحقق من عدم كونها إيجابية كاذبة
                    if not self._is_common_pattern_false_positive(text, context):
                        self.results['suspicious_code'].append({
                            'pattern': text,
                            'offset': offset,
                            'context': binascii.hexlify(context).decode('ascii'),
                            'severity': 'medium'
                        })
                        
                        # إضافة التهديد إذا لم يكن موجودًا بالفعل
                        if len(self.results['suspicious_code']) > 2:  # الحد الأدنى للتهديدات
                            threat_name = "Suspicious code pattern detected"
                            if threat_name not in self.results['detected_threats']:
                                self.results['detected_threats'].append(threat_name)
    
    def _validate_code_threat(self, pattern, context, offset):
        """التحقق من أن نمط التهديد حقيقي وليس إيجابيًا كاذبًا"""
        # التحقق من وجود مؤشرات إضافية للتهديد
        threat_indicators = [
            b'wget', b'curl', b'download', b'upload', b'backdoor', b'rootkit', 
            b'trojan', b'malware', b'exploit', b'.exe', b'.sh', b'.php'
        ]
        
        # عدد المؤشرات التي تم العثور عليها
        indicator_count = 0
        for indicator in threat_indicators:
            if indicator in context:
                indicator_count += 1
        
        # إذا كانت الأنماط شديدة الخطورة، نحتاج مؤشرات أقل
        if pattern in [br'<\?php', br'system\s*\(', br'shell_exec\s*\(', br'cmd\.exe', br'\/bin\/bash']:
            return True  # هذه الأنماط خطيرة بطبيعتها
        
        # إلا نحتاج على الأقل مؤشر واحد إضافي
        return indicator_count > 0
    
    def _is_common_pattern_false_positive(self, text, context):
        """التحقق من الأنماط الشائعة التي قد تكون إيجابيات كاذبة"""
        # النصوص التي تظهر عادة في بيانات الصور الطبيعية
        common_image_strings = [
            'http://', 'https://', 'www.', '.com', '.net', '.org',  # URLs عادية
            '0x0', '0x1', '0x2', '0x3', '0x4', '0x5',  # قيم سداسية شائعة
            'AES', 'XOR', 'Adobe', 'Photoshop', 'GIMP'  # كلمات تقنية شائعة
        ]
        
        # التحقق من السلاسل الشائعة
        for common_string in common_image_strings:
            if common_string in text:
                return True  # يبدو كإيجابي كاذب
        
        # التحقق من لون أو قيمة سداسية
        if re.search(r'^0x[0-9a-fA-F]+$', text):
            return True  # قيمة سداسية منفردة
        
        # التحقق من عنوان IP
        if re.search(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', text):
            return True  # عنوان IP عادي
        
        # افتراضيًا، ليس إيجابيًا كاذبًا
        return False
    
    def _check_data_after_eof(self, image_path, file_data):
        """التحقق من وجود بيانات بعد نهاية ملف الصورة"""
        try:
            # فتح الصورة باستخدام PIL وتحديد حجم البيانات الفعلية
            with Image.open(image_path) as img:
                # استخدام BytesIO لمعرفة الحجم الفعلي للصورة بعد الحفظ
                temp_buffer = io.BytesIO()
                img.save(temp_buffer, format=img.format)
                expected_size = temp_buffer.tell()
                
                # مقارنة الحجم المتوقع بالحجم الفعلي
                actual_size = len(file_data)
                
                # إذا كان الحجم الفعلي أكبر، فهناك بيانات إضافية
                if actual_size > expected_size + 100:  # هامش أمان
                    excess_data = file_data[expected_size:]
                    
                    # تحليل البيانات الإضافية
                    self.results['metadata_anomalies'].append({
                        'type': 'Data after EOF',
                        'size': actual_size - expected_size,
                        'sample': binascii.hexlify(excess_data[:50]).decode('ascii') + '...'
                    })
                    
                    # فحص البيانات الإضافية بحثًا عن أنماط مشبوهة
                    for pattern in self.suspicious_patterns:
                        if re.search(pattern, excess_data):
                            self.results['metadata_anomalies'].append({
                                'type': 'Suspicious pattern in EOF data',
                                'pattern': pattern
                            })
                            
                            # إضافة التهديد المكتشف
                            threat_name = "Data hidden after image EOF"
                            if threat_name not in self.results['detected_threats']:
                                self.results['detected_threats'].append(threat_name)
        
        except Exception as e:
            self.results['metadata_anomalies'].append({
                'type': 'Error checking EOF data',
                'error': str(e)
            })
    
    def _analyze_lsb_steganography(self, image_path):
        """تحليل البيانات المخفية باستخدام تقنية LSB (Least Significant Bit)"""
        try:
            # فتح الصورة وتحويلها إلى مصفوفة
            img = Image.open(image_path)
            
            # التأكد من أن الصورة بصيغة RGB أو RGBA
            if img.mode not in ('RGB', 'RGBA'):
                img = img.convert('RGB')
                
            pixels = np.array(img)
            
            # استخراج القناة الأقل أهمية لكل قناة لون
            lsb_red = pixels[:,:,0] & 1    # البت الأقل أهمية من القناة الحمراء
            lsb_green = pixels[:,:,1] & 1  # البت الأقل أهمية من القناة الخضراء
            lsb_blue = pixels[:,:,2] & 1   # البت الأقل أهمية من القناة الزرقاء
            
            # حساب نسبة البتات المستخدمة في كل قناة
            red_usage = np.sum(lsb_red) / lsb_red.size
            green_usage = np.sum(lsb_green) / lsb_green.size
            blue_usage = np.sum(lsb_blue) / lsb_blue.size
            
            # حساب الانتروبيا (مقياس للعشوائية) في بيانات LSB
            def calculate_entropy(data):
                # تحويل المصفوفة إلى قائمة من 0 و 1
                value, counts = np.unique(data, return_counts=True)
                probs = counts / len(data.flatten())
                entropy = -np.sum(probs * np.log2(probs))
                return entropy
                
            red_entropy = calculate_entropy(lsb_red)
            green_entropy = calculate_entropy(lsb_green)
            blue_entropy = calculate_entropy(lsb_blue)
            
            # تخزين النتائج
            self.results['lsb_analysis'] = {
                'red_usage_percentage': red_usage * 100,
                'green_usage_percentage': green_usage * 100,
                'blue_usage_percentage': blue_usage * 100,
                'red_entropy': red_entropy,
                'green_entropy': green_entropy,
                'blue_entropy': blue_entropy
            }
            
            # تحليل النتائج للكشف عن البيانات المخفية
            # البيانات المخفية عادة ما تكون ذات انتروبيا عالية
            # ونسبة استخدام قريبة من 50%
            
            # عتبات مضبوطة لتقليل الإنذارات الكاذبة
            entropy_threshold = 0.95  # زيادة عتبة الانتروبيا لتقليل الإيجابيات الكاذبة
            usage_threshold = 0.35   # تضييق نطاق نسبة الاستخدام المشبوهة
            
            # فحص أكثر دقة للقنوات الثلاثة
            red_suspicious = red_entropy > entropy_threshold and abs(red_usage - 0.5) < usage_threshold
            green_suspicious = green_entropy > entropy_threshold and abs(green_usage - 0.5) < usage_threshold
            blue_suspicious = blue_entropy > entropy_threshold and abs(blue_usage - 0.5) < usage_threshold
            
            # نحتاج على الأقل قناتين مشبوهتين لتأكيد وجود بيانات مخفية
            suspicious_channels_count = sum([red_suspicious, green_suspicious, blue_suspicious])
            
            # تحليل فرق الانتروبيا بين القنوات
            # عادة ما تكون القيم متشابهة إذا تم حقن بيانات بطريقة منهجية
            entropy_diff = max([abs(red_entropy - green_entropy),
                               abs(red_entropy - blue_entropy),
                               abs(green_entropy - blue_entropy)])
            uniform_channels = entropy_diff < 0.05  # الفرق بين القنوات صغير
            
            # الانتروبيا العالية جدًا تعتبر مؤشرًا قويًا
            very_high_entropy = (red_entropy > 0.98 and green_entropy > 0.98 and blue_entropy > 0.98)
            
            if (suspicious_channels_count >= 2 and uniform_channels) or very_high_entropy:
                self.results['lsb_analysis']['suspicious'] = True
                self.results['lsb_analysis']['reason'] = "High entropy and uniform bit distribution"
                
                # إضافة التهديد المكتشف
                threat_name = "LSB steganography detected"
                if threat_name not in self.results['detected_threats']:
                    self.results['detected_threats'].append(threat_name)
            else:
                self.results['lsb_analysis']['suspicious'] = False
                
        except Exception as e:
            self.results['lsb_analysis']['error'] = str(e)
    
    def _analyze_color_saturation(self, image_path):
        """تحليل تشبع الألوان للكشف عن التغييرات المشبوهة"""
        try:
            # فتح الصورة وتحويلها إلى مصفوفة
            img = Image.open(image_path)
            
            # التأكد من أن الصورة بصيغة RGB
            if img.mode != 'RGB':
                img = img.convert('RGB')
                
            pixels = np.array(img)
            
            # حساب الانحراف المعياري والمتوسط لكل قناة لون
            red_std = np.std(pixels[:,:,0])
            green_std = np.std(pixels[:,:,1])
            blue_std = np.std(pixels[:,:,2])
            
            red_mean = np.mean(pixels[:,:,0])
            green_mean = np.mean(pixels[:,:,1])
            blue_mean = np.mean(pixels[:,:,2])
            
            # حساب معامل التباين (CV) لكل قناة
            red_cv = red_std / red_mean if red_mean > 0 else 0
            green_cv = green_std / green_mean if green_mean > 0 else 0
            blue_cv = blue_std / blue_mean if blue_mean > 0 else 0
            
            # البحث عن مناطق ذات قيم مشبوهة (متجاورة متشابهة بشكل غريب)
            suspicious_regions = []
            
            # تقسيم الصورة إلى شبكة 8×8 وفحص كل منطقة
            height, width, _ = pixels.shape
            block_size = min(height, width) // 8
            
            if block_size > 0:
                for y in range(0, height-block_size, block_size):
                    for x in range(0, width-block_size, block_size):
                        block = pixels[y:y+block_size, x:x+block_size, :]
                        
                        # حساب معامل التباين للكتلة
                        block_cv = [
                            np.std(block[:,:,0]) / (np.mean(block[:,:,0]) + 1e-6),
                            np.std(block[:,:,1]) / (np.mean(block[:,:,1]) + 1e-6),
                            np.std(block[:,:,2]) / (np.mean(block[:,:,2]) + 1e-6)
                        ]
                        
                        # معايير أكثر دقة للمناطق المشبوهة
                        # عتبة أكثر صرامة للتباين المنخفض
                        if (block_cv[0] < 0.05 and 
                            block_cv[1] < 0.05 and 
                            block_cv[2] < 0.05 and
                            np.mean(block) > 30):  # تجنب المناطق الداكنة
                            
                            # تحليل LSB للمنطقة المشبوهة
                            try:
                                # استخراج LSB لكل قناة
                                lsb_red = block[:,:,0] & 1
                                lsb_green = block[:,:,1] & 1
                                lsb_blue = block[:,:,2] & 1
                                
                                # حساب نسبة التوزيع
                                red_ones = np.sum(lsb_red) / lsb_red.size
                                green_ones = np.sum(lsb_green) / lsb_green.size
                                blue_ones = np.sum(lsb_blue) / lsb_blue.size
                                
                                # التحقق من توزيع متوازن للـ LSB
                                if (abs(red_ones - 0.5) < 0.1 or 
                                    abs(green_ones - 0.5) < 0.1 or 
                                    abs(blue_ones - 0.5) < 0.1):
                                    
                                    suspicious_regions.append({
                                        'position': [x, y],
                                        'size': block_size,
                                        'cv': block_cv
                                    })
                            except Exception:
                                pass
            
            self.results['pixel_anomalies'] = {
                'red_cv': red_cv,
                'green_cv': green_cv,
                'blue_cv': blue_cv,
                'suspicious_regions_count': len(suspicious_regions),
                'suspicious_regions': suspicious_regions[:5]  # عرض أول 5 مناطق فقط
            }
            
            # إذا كان هناك مناطق مشبوهة كثيرة، إضافة تهديد
            if len(suspicious_regions) > 3:
                threat_name = "Suspicious uniform image regions"
                if threat_name not in self.results['detected_threats']:
                    self.results['detected_threats'].append(threat_name)
                
        except Exception as e:
            self.results['pixel_anomalies']['error'] = str(e)
    
    def _check_invisible_areas(self, image_path):
        """فحص المناطق غير المرئية من الصورة"""
        try:
            img = Image.open(image_path)
            
            # التحقق من وجود قناة alpha
            if 'A' in img.getbands():
                # استخراج قناة alpha
                alpha = np.array(img.getchannel('A'))
                
                # البحث عن مناطق شفافة
                transparent_regions = alpha < 10  # شفافة تقريبًا
                
                # إذا كانت هناك مناطق شفافة، تحقق من وجود بيانات في قنوات الألوان
                if np.any(transparent_regions):
                    # تحويل الصورة إلى مصفوفة
                    pixels = np.array(img)
                    
                    # فحص قنوات RGB في المناطق الشفافة
                    color_in_transparent = False
                    
                    # فحص كل قناة لون
                    for channel in range(3):  # RGB
                        if channel < pixels.shape[2]:
                            # فحص ما إذا كانت هناك بيانات غير صفرية في المناطق الشفافة
                            if np.any(pixels[:,:,channel][transparent_regions] > 0):
                                color_in_transparent = True
                                break
                    
                    if color_in_transparent:
                        self.results['pixel_anomalies']['invisible_data'] = True
                        
                        # إضافة التهديد المكتشف
                        threat_name = "Data hidden in transparent regions"
                        if threat_name not in self.results['detected_threats']:
                            self.results['detected_threats'].append(threat_name)
                    else:
                        self.results['pixel_anomalies']['invisible_data'] = False
                
        except Exception as e:
            if 'pixel_anomalies' not in self.results:
                self.results['pixel_anomalies'] = {}
            self.results['pixel_anomalies']['invisible_data_error'] = str(e)
    
    def _check_embedded_archives(self, file_data):
        """فحص وجود ملفات مضغوطة مدمجة"""
        try:
            # محاولة استخراج ملفات ZIP محتملة
            temp_data = io.BytesIO(file_data)
            
            # التحقق من ZIP
            try:
                with zipfile.ZipFile(temp_data) as zf:
                    file_list = zf.namelist()
                    if file_list:
                        self.results['embedded_files'].append({
                            'type': 'Embedded ZIP archive',
                            'content': file_list
                        })
                        
                        # إضافة التهديد المكتشف
                        threat_name = "Embedded ZIP archive"
                        if threat_name not in self.results['detected_threats']:
                            self.results['detected_threats'].append(threat_name)
            except:
                pass
            
            # إعادة ضبط موضع البداية
            temp_data.seek(0)
            
            # التحقق من TAR
            try:
                with tarfile.open(fileobj=temp_data, mode='r') as tf:
                    file_list = tf.getnames()
                    if file_list:
                        self.results['embedded_files'].append({
                            'type': 'Embedded TAR archive',
                            'content': file_list
                        })
                        
                        # إضافة التهديد المكتشف
                        threat_name = "Embedded TAR archive"
                        if threat_name not in self.results['detected_threats']:
                            self.results['detected_threats'].append(threat_name)
            except:
                pass
                
        except Exception as e:
            if 'embedded_files_error' not in self.results:
                self.results['embedded_files_error'] = str(e)
    
    def _calculate_risk_score(self):
        """حساب درجة خطورة الصورة بناءً على جميع العوامل مع تقليل الإنذارات الكاذبة"""
        risk_score = 0.0
        threat_indicators = 0  # عدد مؤشرات التهديد
        evidence_strength = []  # تخزين قوة كل دليل
        
        # 1. وجود ملفات مضمنة
        embedded_files_count = len(self.results['embedded_files'])
        if embedded_files_count > 0:
            # التحقق من نوع الملفات المضمنة - بعضها أكثر خطورة
            dangerous_files = 0
            for embedded_file in self.results['embedded_files']:
                file_type = embedded_file.get('type', '')
                if any(keyword in file_type.lower() for keyword in ['exe', 'script', 'php', 'bash', 'elf']):
                    dangerous_files += 1
            
            if dangerous_files > 0:
                risk_score += min(0.6, 0.15 * dangerous_files)
                threat_indicators += 1
                evidence_strength.append(0.9)  # دليل قوي
            else:
                # قد تكون ملفات مضمنة طبيعية
                risk_score += min(0.2, 0.05 * embedded_files_count)
                evidence_strength.append(0.4)  # دليل متوسط
        
        # 2. وجود أكواد مشبوهة
        # التحقق من خطورة الأكواد
        high_severity_code = 0
        for code in self.results['suspicious_code']:
            severity = code.get('severity', 'medium')
            if severity == 'high':
                high_severity_code += 1
        
        if high_severity_code > 0:
            risk_score += min(0.7, 0.2 * high_severity_code)
            threat_indicators += 1
            evidence_strength.append(0.85)  # دليل قوي جدًا
        elif len(self.results['suspicious_code']) > 2:  # عدة أكواد مشبوهة متوسطة
            risk_score += min(0.5, 0.1 * len(self.results['suspicious_code']))
            threat_indicators += 1
            evidence_strength.append(0.6)  # دليل متوسط
        
        # 3. وجود بيانات مخفية في LSB
        if self.results.get('lsb_analysis', {}).get('suspicious', False):
            # التحقق من علامات إضافية
            red_entropy = self.results.get('lsb_analysis', {}).get('red_entropy', 0)
            green_entropy = self.results.get('lsb_analysis', {}).get('green_entropy', 0)
            blue_entropy = self.results.get('lsb_analysis', {}).get('blue_entropy', 0)
            
            # الانتروبيا العالية جدًا تعني احتمالية عالية للتهديد
            if red_entropy > 0.97 or green_entropy > 0.97 or blue_entropy > 0.97:
                risk_score += 0.6
                threat_indicators += 1
                evidence_strength.append(0.9)  # دليل قوي جدًا
            else:
                risk_score += 0.3
                evidence_strength.append(0.7)  # دليل متوسط
                
        # 4. وجود بيانات بعد EOF
        if any(anomaly.get('type') == 'Data after EOF' for anomaly in self.results.get('metadata_anomalies', [])):
            # التحقق من حجم البيانات الإضافية
            for anomaly in self.results.get('metadata_anomalies', []):
                if anomaly.get('type') == 'Data after EOF':
                    size = anomaly.get('size', 0)
                    if size > 1000:  # بيانات إضافية كبيرة
                        risk_score += 0.4
                        threat_indicators += 1
                        evidence_strength.append(0.8)  # دليل قوي
                    else:
                        risk_score += 0.2
                        evidence_strength.append(0.5)  # دليل متوسط
        
        # 5. وجود بيانات في مناطق شفافة
        if self.results.get('pixel_anomalies', {}).get('invisible_data', False):
            risk_score += 0.3
            threat_indicators += 1
            evidence_strength.append(0.6)  # دليل متوسط
            
        # 6. وجود مناطق مشبوهة في الصورة
        suspicious_regions_count = self.results.get('pixel_anomalies', {}).get('suspicious_regions_count', 0)
        if suspicious_regions_count > 5:  # زيادة العتبة لتقليل الإنذارات الكاذبة
            risk_score += min(0.3, 0.05 * suspicious_regions_count)
            threat_indicators += 1
            evidence_strength.append(0.4)  # دليل متوسط
        
        # معالجة خاصة لتقليل الإنذارات الكاذبة
        # لا نعتبر الصورة خطيرة إلا إذا كان لديها أدلة كافية
        # نحتاج إما عدد كافٍ من المؤشرات أو دليل قوي جدًا
        
        # بناء الثقة في النتيجة بناءً على قوة الأدلة
        has_strong_evidence = any(strength > 0.85 for strength in evidence_strength)
        multiple_evidences = threat_indicators >= 2
        
        # تخفيض درجة الخطورة إذا لم يكن هناك أدلة قوية كافية
        if not has_strong_evidence and not multiple_evidences:
            risk_score = risk_score * 0.6  # تخفيض كبير لدرجة الخطورة
        elif not has_strong_evidence and multiple_evidences:
            risk_score = risk_score * 0.8  # تخفيض معتدل
        
        # تخزين المعلومات الإضافية لتقديمها في التقرير
        self.results['risk_confidence'] = {
            'threat_indicators': threat_indicators,
            'has_strong_evidence': has_strong_evidence,
            'multiple_evidences': multiple_evidences,
        }
        
        # ضمان أن الدرجة بين 0 و 1
        self.results['risk_score'] = min(1.0, risk_score)
        
        # تصنيف الخطورة بناءً على الدرجة النهائية
        if risk_score < 0.35:  # زيادة عتبة الخطورة المنخفضة
            self.results['risk_level'] = 'Low'
        elif risk_score < 0.65:  # عتبة الخطورة المتوسطة
            self.results['risk_level'] = 'Medium'
        else:
            self.results['risk_level'] = 'High'
