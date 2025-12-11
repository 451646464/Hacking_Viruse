// كود للتعامل مع حذف الحساب
document.addEventListener('DOMContentLoaded', function() {
    // أزرار حذف الحساب
    const deleteAccountBtn = document.getElementById('deleteAccountBtn');
    const deleteConfirm = document.getElementById('deleteConfirm');
    const cancelDelete = document.getElementById('cancelDelete');
    const confirmDelete = document.getElementById('confirmDelete');
    
    // إظهار/إخفاء نموذج تأكيد الحذف
    if (deleteAccountBtn && deleteConfirm) {
        deleteAccountBtn.addEventListener('click', function() {
            deleteConfirm.classList.remove('hidden');
        });
    }
    
    // إلغاء الحذف
    if (cancelDelete && deleteConfirm) {
        cancelDelete.addEventListener('click', function() {
            deleteConfirm.classList.add('hidden');
        });
    }
    
    // تأكيد الحذف
    if (confirmDelete) {
        confirmDelete.addEventListener('click', function() {
            const password = document.getElementById('deletePassword').value;
            
            if (!password) {
                alert('يرجى إدخال كلمة المرور للتأكيد');
                return;
            }
            
            // تعطيل الزر ليظهر أن العملية قيد التنفيذ
            this.disabled = true;
            this.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i> جاري الحذف...';
            
            // إرسال طلب حذف الحساب (هنا يمكن إضافة الرمز الفعلي للاتصال بالخادم)
            setTimeout(function() {
                alert('تم حذف الحساب بنجاح!');
                window.location.href = '/logout'; // توجيه المستخدم إلى صفحة تسجيل الخروج
            }, 1500);
        });
    }
});
