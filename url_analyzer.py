import joblib
import pandas as pd
import requests
import ssl
import socket
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import re
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import time
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from datetime import datetime
import whois
import dns.resolver
from urllib3.exceptions import MaxRetryError, NewConnectionError, NameResolutionError
from requests.exceptions import RequestException, ConnectionError, Timeout

# تحميل نموذج التصنيف المدرب
model = joblib.load('models/URL/voting_classifier_hard.pkl')

phishing_keywords = [
    "password", "verify", "account", "login", "update", "security", "bank", "confirm",
    "click here", "urgent", "limited time", "risk", "suspend", "alert", "failure"
]

nltk.download('punkt')
nltk.download('stopwords')


def setup_selenium():
    options = Options()
    options.add_argument("--headless")
    options.add_argument('--disable-gpu')
    options.add_argument('--no-sandbox')
    driver = webdriver.Chrome(options=options)
    return driver


def check_ssl_cert(url):
    try:
        parsed_url = urlparse(url)
        if not parsed_url.hostname:
            return False, "لا يوجد نطاق صالح في الرابط"

        hostname = parsed_url.hostname
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get('notAfter')
                expire_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                if expire_date < datetime.utcnow():
                    return False, "الشهادة منتهية الصلاحية"
                return True, "الشهادة صالحة"
    except socket.timeout:
        return False, "انتهت مهلة الاتصال بالخادم"
    except ConnectionRefusedError:
        return False, "تم رفض الاتصال بالخادم"
    except socket.gaierror:
        return False, "تعذر حل النطاق (DNS)"
    except Exception as e:
        return False, f"خطأ في فحص الشهادة: {str(e)}"


def analyze_text_content(text):
    text = text.lower()
    tokens = word_tokenize(text)
    stop_words = set(stopwords.words('english'))
    filtered_words = [w for w in tokens if w.isalpha() and w not in stop_words]
    for word in filtered_words:
        if word in phishing_keywords:
            return False, f"وجود كلمة مشبوهة: {word}"
    return True, "لا توجد كلمات مشبوهة"


def analyze_html(html_content, url):
    soup = BeautifulSoup(html_content, 'html.parser')
    forms = soup.find_all('form')
    for form in forms:
        form_text = form.get_text().lower()
        if any(keyword in form_text for keyword in ["password", "credit card", "ssn", "social security", "pin"]):
            return False, "نموذج يطلب معلومات حساسة"
    scripts = soup.find_all('script')
    for script in scripts:
        if script.string and ('eval(' in script.string or 'unescape(' in script.string):
            return False, "وجود سكريبتات تشفير أو إخفاء محتوى"
    anchors = soup.find_all('a', href=True)
    suspicious_domains = 0
    main_domain = urlparse(url).netloc
    for a in anchors:
        link_domain = urlparse(a['href']).netloc
        if link_domain and link_domain != main_domain:
            suspicious_domains += 1
    if suspicious_domains > 15:
        return False, "وجود روابط كثيرة إلى نطاقات مختلفة مشبوهة"
    meta_redirect = soup.find('meta', attrs={'http-equiv': 'refresh'})
    if meta_redirect:
        return False, "وجود إعادة توجيه داخل الصفحة"
    return True, "تحليل HTML طبيعي"


def get_domain_age(domain):
    try:
        if not domain:
            return -1

        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date is None:
            return -1  # غير معروف
        age_days = (datetime.utcnow() - creation_date).days
        if age_days < 180:  # أقل من 6 أشهر
            return -1
        elif age_days < 365 * 2:
            return 0
        else:
            return 1
    except Exception:
        return -1


def has_dns_record(domain):
    try:
        if not domain:
            return -1

        answers = dns.resolver.resolve(domain, 'A')
        if answers:
            return 1
        return -1
    except Exception:
        return -1


def extract_features_from_url(url):
    features = {}
    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
    features['having_IP'] = -1 if ip_pattern.search(url) else 1

    length = len(url)
    if length < 54:
        features['URL_Length'] = -1
    elif length <= 75:
        features['URL_Length'] = 0
    else:
        features['URL_Length'] = 1

    short_services = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly']
    features['Shortining_Service'] = -1 if any(s in url for s in short_services) else 1

    features['having_At_Symbol'] = -1 if '@' in url else 1

    double_slash_pos = url.find('//', url.find('://') + 3)
    features['double_slash_redirecting'] = 1 if double_slash_pos != -1 else -1

    features['Prefix_Suffix'] = -1 if '-' in domain else 1

    dots = domain.count('.')
    if dots == 1:
        features['having_Sub_Domain'] = 1
    elif dots == 2:
        features['having_Sub_Domain'] = 0
    else:
        features['having_Sub_Domain'] = -1

    features['SSLfinal_State'] = 1 if parsed_url.scheme == 'https' else -1

    # طول الدومين
    features['Domain_registeration_length'] = 1 if len(domain) > 15 else -1

    features['Favicon'] = 1  # تبسيط

    port = parsed_url.port
    if port is None or port in [80, 443]:
        features['port'] = 1
    else:
        features['port'] = -1

    features['HTTPS_token'] = -1 if 'https' in domain else 1

    features['Request_URL'] = 1
    features['URL_of_Anchor'] = 1
    features['Links_in_tags'] = 1
    features['SFH'] = 1
    features['Submitting_to_email'] = 1
    features['Abnormal_URL'] = 1
    features['Redirect'] = 0
    features['on_mouseover'] = 0
    features['RightClick'] = 0
    features['popUpWidnow'] = 0
    features['Iframe'] = 0

    # العمر بناءً على WHOIS
    features['age_of_domain'] = get_domain_age(domain)

    # سجلات DNS حقيقية
    features['DNSRecord'] = has_dns_record(domain)

    # الميزات التي لا تتوفر بيانات حقيقية لها: نفترض 0 (يمكن تحسينها لاحقاً)
    features['web_traffic'] = 0
    features['Page_Rank'] = 0
    features['Google_Index'] = 0
    features['Links_pointing_to_page'] = 0
    features['Statistical_report'] = 0

    return pd.DataFrame([features])


def virustotal_scan(url, api_key):
    if not api_key or api_key.strip() == "":
        return None, "مفتاح API غير متوفر"

    headers = {"x-apikey": api_key}
    scan_url = "https://www.virustotal.com/api/v3/urls"

    try:
        # 1. إرسال الرابط للفحص
        response = requests.post(scan_url, headers=headers, data={'url': url}, timeout=30)
        if response.status_code != 200:
            return None, f"خطأ في إرسال الرابط إلى VirusTotal: {response.status_code}"

        result = response.json()
        url_id = result['data']['id']

        # 2. الانتظار لضمان اكتمال الفحص
        max_retries = 3
        report = None
        for attempt in range(max_retries):
            time.sleep(15)
            report_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"
            report_response = requests.get(report_url, headers=headers, timeout=30)
            if report_response.status_code == 200:
                report = report_response.json()
                if report['data']['attributes']['status'] == 'completed':
                    break
        else:
            return None, "فشل في الحصول على تقرير مكتمل بعد عدة محاولات"

        # 3. تحليل النتائج
        stats = report['data']['attributes']['stats']
        result_text = f"""
        <b>نتائج VirusTotal:</b>
        <ul>
            <li>مجموع الفحوصات: {sum(stats.values())}</li>
            <li>الفحوصات الخبيثة: {stats.get('malicious', 0)}</li>
            <li>الفحوصات المشبوهة: {stats.get('suspicious', 0)}</li>
            <li>الفحوصات النظيفة: {stats.get('harmless', 0)}</li>
            <li>غير مصنف: {stats.get('undetected', 0)}</li>
        </ul>
        """

        # 4. تحديد حالة الرابط
        if stats.get('malicious', 0) > 0:
            return False, f"<b>⚠️ الرابط خبيث:</b><br>{result_text}"
        elif stats.get('suspicious', 0) > 0:
            return False, f"<b>🔍 الرابط مشبوه:</b><br>{result_text}"
        else:
            return True, f"<b>✅ الرابط آمن:</b><br>{result_text}"

    except Timeout:
        return None, "انتهت مهلة الاتصال بـ VirusTotal"
    except ConnectionError:
        return None, "تعذر الاتصال بـ VirusTotal"
    except Exception as e:
        return None, f"خطأ في فحص VirusTotal: {str(e)}"


def analyze_url(url, driver=None, vt_api_key=None):
    """
    تحليل الرابط مع معالجة أخطاء DNS والاستمرار في الفحص
    """

    # استخراج الميزات والتنبؤ الأولي من نموذج التعلم الآلي
    # هذا يعمل حتى لو فشل DNS
    features_df = extract_features_from_url(url)
    pred = model.predict(features_df.values)[0] if not features_df.empty else -1
    original_label = "Phishing" if pred == -1 else "Legitimate"

    # محاولة تحليل DNS وحل النطاق
    dns_success = True
    dns_error = None
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        if domain:
            socket.gethostbyname(domain)
    except socket.gaierror as e:
        dns_success = False
        if e.errno == 11001:
            dns_error = f"تعذر حل النطاق '{domain}'. النطاق غير موجود."
        else:
            dns_error = f"خطأ في حل النطاق: {str(e)}"
    except Exception as e:
        dns_success = False
        dns_error = f"خطأ في فحص DNS: {str(e)}"

    # فحص SSL (قد يفشل إذا فشل DNS)
    ssl_ok, ssl_msg = check_ssl_cert(url)

    # محاولة تحميل المحتوى (فقط إذا نجح DNS)
    html_content = ""
    connection_error = None
    if dns_success:
        try:
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                html_content = response.text
            else:
                connection_error = f"تعذر تحميل الصفحة، رمز الحالة: {response.status_code}"
        except ConnectionError as e:
            connection_error = f"خطأ في الاتصال: {str(e)}"
        except Timeout as e:
            connection_error = f"انتهت مهلة الاتصال: {str(e)}"
        except RequestException as e:
            connection_error = f"خطأ في الطلب: {str(e)}"
    else:
        connection_error = dns_error

    # تحليل المحتوى النصي (فقط إذا كان هناك محتوى)
    if html_content:
        text_ok, text_msg = analyze_text_content(html_content)
    else:
        text_msg = "لا يمكن تحليل المحتوى (تعذر تحميل الصفحة)" if connection_error else "لا يوجد محتوى"

    # تحليل HTML (فقط إذا كان هناك محتوى)
    if html_content:
        html_ok, html_msg = analyze_html(html_content, url)
    else:
        html_msg = "لا يمكن تحليل HTML (تعذر تحميل الصفحة)" if connection_error else "لا يوجد محتوى HTML"

    # فحص جافاسكريبت
    js_msg = "لا توجد سكريبتات مشبوهة"
    if driver and dns_success:
        try:
            driver.get(url)
            time.sleep(5)
            page_source = driver.page_source
            if "eval(" in page_source or "unescape(" in page_source:
                js_msg = "وجود سكريبتات تشفير أو إخفاء محتوى في جافاسكريبت"
        except Exception as e:
            js_msg = f"خطأ في Selenium: {e}"
    elif not dns_success:
        js_msg = "لم يتم إجراء فحص جافاسكريبت (فشل DNS)"
    else:
        js_msg = "لم يتم إجراء فحص جافاسكريبت"

    # فحص VirusTotal
    vt_ok = True
    vt_msg = "لم يتم تفعيل فحص VirusTotal"
    vt_result = None

    vt_malicious = False
    vt_scanned = False

    if vt_api_key:
        vt_result, vt_msg = virustotal_scan(url, vt_api_key)
        if vt_result is None:
            vt_msg = "تعذر الحصول على نتيجة فحص VirusTotal"
        elif vt_result is False:
            vt_ok = False
            vt_malicious = True
            vt_scanned = True
        else:
            vt_malicious = False
            vt_scanned = True

    # تحديد التصنيف النهائي
    final_label = original_label

    if vt_scanned:
        if vt_malicious:
            final_label = "Phishing"
        else:
            final_label = original_label

    # النتيجة النهائية
    if final_label == "Phishing":
        final_result = "(Phishing)"
    else:
        final_result = "(Legitimate)"

    # إضافة ملاحظة إذا تم تغيير التنبؤ الأصلي
    vt_note = ""
    if vt_scanned and original_label != final_label:
        if vt_malicious:
            vt_note = " no open the link"
        else:
            vt_note = " open the link"

    # تجميع النتائج
    result = {
        'url': url,
        'ssl_status': ssl_msg,
        'model_prediction': final_label,
        'original_prediction': original_label,
        'content_analysis': text_msg,
        'html_analysis': html_msg,
        'javascript_analysis': js_msg,
        'virustotal_result': vt_msg + vt_note if vt_note else vt_msg,
        'final_result': final_result + vt_note
    }

    # إضافة معلومات DNS إذا فشلت
    if not dns_success:
        result['dns_error'] = dns_error
        result['warning'] = "تحذير: فشل في حل النطاق - تم إجراء الفحوصات المتاحة فقط"

    # إضافة خطأ الاتصال إذا فشل
    if connection_error:
        result['connection_error'] = connection_error

    return result