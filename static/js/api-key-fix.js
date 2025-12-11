// حل مشكلة مفتاح API - كود مبسط
document.addEventListener('DOMContentLoaded', function() {
    console.log("تم تحميل كود إصلاح مفتاح API");
    
    // أزرار ومكونات واجهة المستخدم
    const apiKeyInput = document.getElementById('apiKeyDisplay');
    const toggleButton = document.getElementById('toggleApiKey');
    const copyButton = document.getElementById('copyApiKey');
    const generateButton = document.getElementById('generateApiKey');
    const revokeButton = document.getElementById('revokeApiKey');
    
    // القيمة الفعلية للمفتاح من البيانات المخزنة في عنصر HTML
    const actualApiKey = apiKeyInput ? apiKeyInput.getAttribute('data-key') : '';
    
    console.log("هل يوجد مفتاح API:", actualApiKey ? "نعم" : "لا");
    
    // 1. إظهار/إخفاء المفتاح
    if (toggleButton && apiKeyInput) {
        toggleButton.addEventListener('click', function() {
            console.log("تم النقر على زر الإظهار/الإخفاء");
            
            if (apiKeyInput.type === 'password' && actualApiKey) {
                // إظهار المفتاح
                apiKeyInput.type = 'text';
                apiKeyInput.value = actualApiKey;
                document.getElementById('toggleIcon').classList.remove('fa-eye');
                document.getElementById('toggleIcon').classList.add('fa-eye-slash');
                console.log("تم إظهار المفتاح");
            } else {
                // إخفاء المفتاح
                apiKeyInput.type = 'password';
                apiKeyInput.value = actualApiKey ? '•••••••••••••••••••' : 'لا يوجد مفتاح API';
                document.getElementById('toggleIcon').classList.remove('fa-eye-slash');
                document.getElementById('toggleIcon').classList.add('fa-eye');
                console.log("تم إخفاء المفتاح");
            }
        });
    }
    
    // 2. نسخ المفتاح
    if (copyButton && actualApiKey) {
        copyButton.addEventListener('click', function() {
            console.log("تم النقر على زر النسخ");
            
            if (!actualApiKey) {
                alert("لا يوجد مفتاح API للنسخ!");
                return;
            }
            
            // طريقة 1: استخدام document.execCommand
            const tempInput = document.createElement('textarea');
            tempInput.style.position = 'absolute';
            tempInput.style.left = '-9999px';
            tempInput.style.top = '0';
            tempInput.value = actualApiKey;
            document.body.appendChild(tempInput);
            tempInput.select();
            tempInput.setSelectionRange(0, 99999);
            
            try {
                const success = document.execCommand('copy');
                if (success) {
                    alert("تم نسخ مفتاح API بنجاح!");
                    console.log("تم نسخ المفتاح بنجاح (طريقة 1)");
                } else {
                    throw new Error("فشل النسخ");
                }
            } catch (err) {
                console.log("فشل النسخ بالطريقة 1، محاولة الطريقة 2...");
                
                // طريقة 2: استخدام Clipboard API
                if (navigator.clipboard) {
                    navigator.clipboard.writeText(actualApiKey)
                        .then(() => {
                            alert("تم نسخ مفتاح API بنجاح!");
                            console.log("تم نسخ المفتاح بنجاح (طريقة 2)");
                        })
                        .catch(err => {
                            console.error("خطأ في نسخ المفتاح:", err);
                            alert("حدث خطأ أثناء نسخ المفتاح!");
                        });
                } else {
                    alert("لا يمكن نسخ المفتاح، يرجى نسخه يدوياً!");
                }
            } finally {
                document.body.removeChild(tempInput);
            }
        });
    } else if (copyButton) {
        copyButton.addEventListener('click', function() {
            alert("لا يوجد مفتاح API للنسخ!");
        });
    }
    
    // 3. توليد مفتاح جديد
    if (generateButton) {
        generateButton.addEventListener('click', function() {
            if (confirm("هل أنت متأكد من توليد مفتاح API جديد؟")) {
                this.disabled = true;
                this.textContent = "جاري التوليد...";
                
                fetch('/api/generate-key', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success && data.api_key) {
                        alert("تم توليد مفتاح API بنجاح!");
                        
                        // تحديث المفتاح في الصفحة
                        apiKeyInput.setAttribute('data-key', data.api_key);
                        apiKeyInput.type = 'password';
                        apiKeyInput.value = '•••••••••••••••••••';
                        
                        // تفعيل الأزرار
                        toggleButton.disabled = false;
                        copyButton.disabled = false;
                        
                        // إظهار زر الإلغاء إذا كان مخفياً
                        if (revokeButton) {
                            revokeButton.style.display = 'inline-flex';
                        }
                        
                        // تحديث الصفحة لتحديث العرض
                        setTimeout(() => window.location.reload(), 1500);
                    } else {
                        alert("حدث خطأ أثناء توليد المفتاح!");
                    }
                })
                .catch(err => {
                    console.error("خطأ في توليد المفتاح:", err);
                    alert("حدث خطأ أثناء الاتصال بالخادم!");
                })
                .finally(() => {
                    this.disabled = false;
                    this.textContent = "توليد مفتاح جديد";
                });
            }
        });
    }
    
    // 4. إلغاء المفتاح
    if (revokeButton) {
        revokeButton.addEventListener('click', function() {
            if (confirm("هل أنت متأكد من إلغاء مفتاح API؟ لن تتمكن من استخدامه بعد الآن!")) {
                this.disabled = true;
                this.textContent = "جاري الإلغاء...";
                
                fetch('/api/revoke-key', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert("تم إلغاء مفتاح API بنجاح!");
                        
                        // تحديث العرض
                        apiKeyInput.setAttribute('data-key', '');
                        apiKeyInput.type = 'text';
                        apiKeyInput.value = 'لا يوجد مفتاح API';
                        
                        // تعطيل الأزرار
                        toggleButton.disabled = true;
                        copyButton.disabled = true;
                        
                        // إخفاء زر الإلغاء
                        this.style.display = 'none';
                        
                        // تحديث الصفحة
                        setTimeout(() => window.location.reload(), 1500);
                    } else {
                        alert("حدث خطأ أثناء إلغاء المفتاح!");
                    }
                })
                .catch(err => {
                    console.error("خطأ في إلغاء المفتاح:", err);
                    alert("حدث خطأ أثناء الاتصال بالخادم!");
                })
                .finally(() => {
                    this.disabled = false;
                    this.textContent = "إلغاء المفتاح";
                });
            }
        });
    }
    
    console.log("تم إعداد كود إصلاح مفتاح API بنجاح!");
});
