// Settings Page JavaScript - Enhanced Version
document.addEventListener('DOMContentLoaded', function() {
    console.log('Settings Enhanced JS loaded');
    
    // ============ TAB FUNCTIONALITY ============
    const tabs = document.querySelectorAll('.settings-tab');
    const contents = document.querySelectorAll('.settings-content');
    
    // Function to show a specific tab
    function showTab(targetId) {
        // Hide all contents
        contents.forEach(content => {
            content.style.display = 'none';
        });
        
        // Show target content
        const targetContent = document.getElementById(targetId);
        if (targetContent) {
            targetContent.style.display = 'block';
        }
        
        // Update tab styles
        tabs.forEach(tab => {
            const href = tab.getAttribute('href');
            if (href === '#' + targetId) {
                tab.classList.add('active', 'bg-gray-700/50', 'text-white');
                tab.classList.remove('text-gray-300');
            } else {
                tab.classList.remove('active', 'bg-gray-700/50', 'text-white');
                tab.classList.add('text-gray-300');
            }
        });
    }
    
    // Handle tab clicks
    tabs.forEach(tab => {
        tab.addEventListener('click', function(e) {
            e.preventDefault();
            const href = this.getAttribute('href');
            const targetId = href.substring(1);
            showTab(targetId);
            window.location.hash = href;
        });
    });
    
    // Handle direct URL with hash
    const hash = window.location.hash.substring(1);
    if (hash && document.getElementById(hash)) {
        showTab(hash);
    } else {
        showTab('profile');
    }
    
    // ============ API KEY MANAGEMENT - ENHANCED ============
    const toggleApiKeyBtn = document.getElementById('toggleApiKey');
    const apiKeyDisplay = document.getElementById('apiKeyDisplay');
    const actualApiKey = document.getElementById('actualApiKey');
    const toggleIcon = document.getElementById('toggleIcon');
    const copyApiKeyBtn = document.getElementById('copyApiKey');
    const generateApiKeyBtn = document.getElementById('generateApiKey');
    const revokeApiKeyBtn = document.getElementById('revokeApiKey');
    
    // Toggle API Key visibility - ENHANCED
    if (toggleApiKeyBtn && apiKeyDisplay && actualApiKey) {
        toggleApiKeyBtn.addEventListener('click', function() {
            const key = actualApiKey.value;
            
            if (key && key !== '') {
                if (apiKeyDisplay.type === 'password') {
                    apiKeyDisplay.type = 'text';
                    apiKeyDisplay.value = key;
                    
                    if (toggleIcon) {
                        toggleIcon.classList.remove('fa-eye');
                        toggleIcon.classList.add('fa-eye-slash');
                    }
                } else {
                    apiKeyDisplay.type = 'password';
                    apiKeyDisplay.value = '•••••••••••••••••••';
                    
                    if (toggleIcon) {
                        toggleIcon.classList.remove('fa-eye-slash');
                        toggleIcon.classList.add('fa-eye');
                    }
                }
            }
        });
    }
    
    // Copy API Key - ENHANCED
    if (copyApiKeyBtn) {
        copyApiKeyBtn.addEventListener('click', function() {
            // Get key from hidden field
            const key = actualApiKey.value;
            
            if (key && key !== '') {
                // Create a temporary input for copying
                const tempInput = document.createElement('input');
                tempInput.value = key;
                document.body.appendChild(tempInput);
                tempInput.select();
                
                try {
                    // Try to copy to clipboard
                    document.execCommand('copy');
                    showToast('تم نسخ مفتاح API بنجاح', 'success');
                } catch (err) {
                    // Fallback to modern clipboard API
                    navigator.clipboard.writeText(key)
                        .then(() => {
                            showToast('تم نسخ مفتاح API بنجاح', 'success');
                        })
                        .catch(() => {
                            showToast('فشل في نسخ المفتاح. حاول مرة أخرى', 'error');
                        });
                } finally {
                    // Clean up
                    document.body.removeChild(tempInput);
                }
            } else {
                showToast('لا يوجد مفتاح API للنسخ', 'error');
            }
        });
    }
    
    // Generate API Key - ENHANCED
    if (generateApiKeyBtn) {
        generateApiKeyBtn.addEventListener('click', function() {
            if (confirm('هل أنت متأكد من توليد مفتاح API جديد؟ سيتم إلغاء المفتاح السابق إن وجد.')) {
                // Show loading
                this.innerHTML = '<i class="fas fa-spinner fa-spin"></i> جاري التوليد...';
                this.disabled = true;
                
                fetch('/api/generate-key', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        if (apiKeyDisplay && actualApiKey) {
                            apiKeyDisplay.type = 'password';
                            apiKeyDisplay.value = '•••••••••••••••••••';
                            actualApiKey.value = data.api_key;
                        }
                        
                        if (copyApiKeyBtn) copyApiKeyBtn.disabled = false;
                        if (toggleApiKeyBtn) toggleApiKeyBtn.disabled = false;
                        if (revokeApiKeyBtn) {
                            revokeApiKeyBtn.style.display = 'inline-flex';
                        }
                        
                        showToast('تم توليد مفتاح API جديد بنجاح', 'success');
                    } else {
                        showToast(data.message || 'فشل توليد مفتاح API', 'error');
                    }
                })
                .catch(error => {
                    showToast('حدث خطأ أثناء توليد مفتاح API', 'error');
                })
                .finally(() => {
                    // Restore button
                    this.innerHTML = '<i class="fas fa-sync-alt"></i> <span>توليد مفتاح جديد</span>';
                    this.disabled = false;
                });
            }
        });
    }
    
    // Revoke API Key
    if (revokeApiKeyBtn) {
        revokeApiKeyBtn.addEventListener('click', function() {
            if (confirm('هل أنت متأكد من إلغاء مفتاح API؟ لن تتمكن من استخدامه بعد الآن.')) {
                // Show loading
                this.innerHTML = '<i class="fas fa-spinner fa-spin"></i> جاري الإلغاء...';
                this.disabled = true;
                
                fetch('/api/revoke-key', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        if (apiKeyDisplay && actualApiKey) {
                            apiKeyDisplay.value = 'لا يوجد مفتاح API';
                            apiKeyDisplay.type = 'text';
                            actualApiKey.value = '';
                        }
                        
                        if (copyApiKeyBtn) copyApiKeyBtn.disabled = true;
                        if (toggleApiKeyBtn) toggleApiKeyBtn.disabled = true;
                        
                        // Hide revoke button
                        this.style.display = 'none';
                        
                        // Update generate button
                        if (generateApiKeyBtn) {
                            generateApiKeyBtn.innerHTML = '<i class="fas fa-sync-alt"></i> <span>توليد مفتاح جديد</span>';
                        }
                        
                        showToast('تم إلغاء مفتاح API بنجاح', 'success');
                    } else {
                        showToast(data.message || 'فشل إلغاء مفتاح API', 'error');
                        
                        // Restore button
                        this.innerHTML = '<i class="fas fa-times-circle"></i> <span>إلغاء المفتاح</span>';
                        this.disabled = false;
                    }
                })
                .catch(error => {
                    showToast('حدث خطأ أثناء إلغاء مفتاح API', 'error');
                    
                    // Restore button
                    this.innerHTML = '<i class="fas fa-times-circle"></i> <span>إلغاء المفتاح</span>';
                    this.disabled = false;
                });
            }
        });
    }
    
    // Form Submission with Animations
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Get submit button
            const submitBtn = this.querySelector('button[type="submit"]');
            if (!submitBtn) return;
            
            // Store original content
            const originalContent = submitBtn.innerHTML;
            
            // Show loading animation
            submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> جاري الحفظ...';
            submitBtn.disabled = true;
            
            // Submit form
            fetch(this.action, {
                method: this.method,
                body: new FormData(this)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showToast(data.message || 'تم الحفظ بنجاح', 'success');
                    
                    // Show success animation
                    submitBtn.innerHTML = '<i class="fas fa-check"></i> تم الحفظ';
                    setTimeout(() => {
                        submitBtn.innerHTML = originalContent;
                        submitBtn.disabled = false;
                    }, 1500);
                } else {
                    showToast(data.message || 'حدث خطأ أثناء الحفظ', 'error');
                    submitBtn.innerHTML = originalContent;
                    submitBtn.disabled = false;
                }
            })
            .catch(error => {
                showToast('حدث خطأ أثناء الاتصال بالخادم', 'error');
                submitBtn.innerHTML = originalContent;
                submitBtn.disabled = false;
            });
        });
    });
    
    // Avatar Upload Preview
    const avatarUpload = document.getElementById('avatarUpload');
    const previewImage = document.getElementById('previewImage');
    const avatarPreview = document.getElementById('avatarPreview');
    const cancelUpload = document.getElementById('cancelUpload');
    const profileImagePreview = document.getElementById('profileImagePreview');
    const profileInitial = document.getElementById('profileInitial');
    
    if (avatarUpload) {
        avatarUpload.addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file) {
                // Check file size
                if (file.size > 2 * 1024 * 1024) {
                    showToast('حجم الملف يجب أن يكون أقل من 2MB', 'error');
                    return;
                }
                
                // Check file type
                if (!['image/jpeg', 'image/png', 'image/gif'].includes(file.type)) {
                    showToast('صيغة الملف غير مدعومة', 'error');
                    return;
                }
                
                const reader = new FileReader();
                reader.onload = function(e) {
                    // Show preview
                    if (previewImage) previewImage.src = e.target.result;
                    if (avatarPreview) avatarPreview.classList.remove('hidden');
                    
                    // Update profile display
                    if (profileImagePreview) {
                        profileImagePreview.src = e.target.result;
                        profileImagePreview.classList.remove('hidden');
                    }
                    if (profileInitial) profileInitial.classList.add('hidden');
                };
                reader.readAsDataURL(file);
            }
        });
    }
    
    if (cancelUpload) {
        cancelUpload.addEventListener('click', function() {
            // Reset file input
            if (avatarUpload) avatarUpload.value = '';
            
            // Hide preview
            if (avatarPreview) avatarPreview.classList.add('hidden');
            
            // Reset profile display to initial state
            if (profileImagePreview && profileImagePreview.dataset.originalSrc) {
                profileImagePreview.src = profileImagePreview.dataset.originalSrc;
                profileImagePreview.classList.remove('hidden');
                if (profileInitial) profileInitial.classList.add('hidden');
            } else {
                if (profileImagePreview) profileImagePreview.classList.add('hidden');
                if (profileInitial) profileInitial.classList.remove('hidden');
            }
        });
    }
    
    // Password Validation
    const newPassword = document.getElementById('newPassword');
    const confirmPassword = document.getElementById('confirmPassword');
    const passwordMatchError = document.getElementById('passwordMatchError');
    
    if (confirmPassword && newPassword && passwordMatchError) {
        confirmPassword.addEventListener('input', function() {
            if (this.value !== newPassword.value) {
                passwordMatchError.classList.remove('hidden');
            } else {
                passwordMatchError.classList.add('hidden');
            }
        });
        
        newPassword.addEventListener('input', function() {
            if (confirmPassword.value && this.value !== confirmPassword.value) {
                passwordMatchError.classList.remove('hidden');
            } else {
                passwordMatchError.classList.add('hidden');
            }
        });
    }
    
    // Toast Notifications
    window.showToast = function(message, type) {
        // Create toast element
        const toast = document.createElement('div');
        toast.className = 'toast ' + type;
        
        // Create content
        const icon = document.createElement('i');
        icon.className = type === 'success' ? 'fas fa-check-circle' : 'fas fa-exclamation-circle';
        icon.style.marginRight = '8px';
        
        const textSpan = document.createElement('span');
        textSpan.textContent = message;
        
        toast.appendChild(icon);
        toast.appendChild(textSpan);
        
        // Add to document
        document.body.appendChild(toast);
        
        // Trigger animation
        setTimeout(() => toast.classList.add('show'), 10);
        
        // Remove after timeout
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => {
                if (document.body.contains(toast)) {
                    document.body.removeChild(toast);
                }
            }, 300);
        }, 3000);
    };
});
