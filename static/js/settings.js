// Settings Page JavaScript
console.log('Settings JS loaded');

document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM loaded');
    
    const tabs = document.querySelectorAll('.settings-tab');
    const contents = document.querySelectorAll('.settings-content');
    
    console.log('Tabs found:', tabs.length);
    console.log('Contents found:', contents.length);
    
    // Function to show a specific tab
    function showTab(targetId) {
        console.log('Showing tab:', targetId);
        
        // Hide all contents
        contents.forEach(content => {
            content.style.display = 'none';
        });
        
        // Show target content
        const targetContent = document.getElementById(targetId);
        if (targetContent) {
            targetContent.style.display = 'block';
            console.log('Tab shown successfully:', targetId);
        } else {
            console.error('Content not found:', targetId);
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
    
    // Handle hash change
    window.addEventListener('hashchange', function() {
        const newHash = window.location.hash.substring(1);
        if (newHash && document.getElementById(newHash)) {
            showTab(newHash);
        }
    });
    
    // ============ API KEY MANAGEMENT ============
    const toggleApiKeyBtn = document.getElementById('toggleApiKey');
    const apiKeyDisplay = document.getElementById('apiKeyDisplay');
    const toggleIcon = document.getElementById('toggleIcon');
    const copyApiKeyBtn = document.getElementById('copyApiKey');
    const generateApiKeyBtn = document.getElementById('generateApiKey');
    const revokeApiKeyBtn = document.getElementById('revokeApiKey');
    
    // Toggle API Key visibility
    if (toggleApiKeyBtn && apiKeyDisplay) {
        toggleApiKeyBtn.addEventListener('click', function() {
            console.log('Toggle API Key clicked');
            if (apiKeyDisplay.type === 'password') {
                apiKeyDisplay.type = 'text';
                toggleIcon.classList.remove('fa-eye');
                toggleIcon.classList.add('fa-eye-slash');
            } else {
                apiKeyDisplay.type = 'password';
                toggleIcon.classList.remove('fa-eye-slash');
                toggleIcon.classList.add('fa-eye');
            }
        });
    }
    
    // Copy API Key
    if (copyApiKeyBtn && apiKeyDisplay) {
        copyApiKeyBtn.addEventListener('click', function() {
            console.log('Copy API Key clicked');
            const apiKey = apiKeyDisplay.dataset.key || apiKeyDisplay.value;
            if (apiKey && apiKey !== 'لا يوجد مفتاح API' && apiKey !== '') {
                navigator.clipboard.writeText(apiKey).then(() => {
                    showToast('تم نسخ مفتاح API بنجاح', 'success');
                    console.log('API Key copied successfully');
                }).catch((err) => {
                    console.error('Failed to copy:', err);
                    showToast('فشل نسخ مفتاح API', 'error');
                });
            } else {
                showToast('لا يوجد مفتاح API للنسخ', 'error');
            }
        });
    }
    
    // Generate API Key
    if (generateApiKeyBtn) {
        generateApiKeyBtn.addEventListener('click', function() {
            console.log('Generate API Key clicked');
            if (confirm('هل أنت متأكد من توليد مفتاح API جديد؟ سيتم إلغاء المفتاح السابق إن وجد.')) {
                fetch('/api/generate-key', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        apiKeyDisplay.value = data.api_key;
                        apiKeyDisplay.dataset.key = data.api_key;
                        copyApiKeyBtn.disabled = false;
                        toggleApiKeyBtn.disabled = false;
                        showToast('تم توليد مفتاح API جديد بنجاح', 'success');
                        setTimeout(() => location.reload(), 1500);
                    } else {
                        showToast(data.message || 'فشل توليد مفتاح API', 'error');
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    showToast('حدث خطأ أثناء توليد مفتاح API', 'error');
                });
            }
        });
    }
    
    // Revoke API Key
    if (revokeApiKeyBtn) {
        revokeApiKeyBtn.addEventListener('click', function() {
            console.log('Revoke API Key clicked');
            if (confirm('هل أنت متأكد من إلغاء مفتاح API؟ لن تتمكن من استخدامه بعد الآن.')) {
                fetch('/api/revoke-key', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        apiKeyDisplay.value = 'لا يوجد مفتاح API';
                        apiKeyDisplay.dataset.key = '';
                        apiKeyDisplay.type = 'password';
                        copyApiKeyBtn.disabled = true;
                        toggleApiKeyBtn.disabled = true;
                        showToast('تم إلغاء مفتاح API بنجاح', 'success');
                        setTimeout(() => location.reload(), 1500);
                    } else {
                        showToast(data.message || 'فشل إلغاء مفتاح API', 'error');
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    showToast('حدث خطأ أثناء إلغاء مفتاح API', 'error');
                });
            }
        });
    }
    
    // ============ THEME SWITCHER ============
    const themeRadios = document.querySelectorAll('input[name="theme"]');
    
    // Load saved theme
    const savedTheme = localStorage.getItem('theme') || 'dark';
    const themeRadio = document.getElementById(`${savedTheme}-theme`);
    if (themeRadio) {
        themeRadio.checked = true;
        applyTheme(savedTheme);
    }
    
    // Handle theme change
    themeRadios.forEach(radio => {
        radio.addEventListener('change', function() {
            console.log('Theme changed to:', this.value);
            applyTheme(this.value);
            localStorage.setItem('theme', this.value);
        });
    });
    
    // Apply theme function
    function applyTheme(theme) {
        if (theme === 'light') {
            document.documentElement.classList.add('light-mode');
            document.body.classList.add('light-mode');
        } else {
            document.documentElement.classList.remove('light-mode');
            document.body.classList.remove('light-mode');
        }
        console.log('Theme applied:', theme);
    }
    
    // ============ TOAST NOTIFICATION ============
    window.showToast = function(message, type) {
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;
        document.body.appendChild(toast);
        
        setTimeout(() => {
            toast.classList.add('show');
        }, 10);
        
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => {
                if (document.body.contains(toast)) {
                    document.body.removeChild(toast);
                }
            }, 300);
        }, 3000);
    }
});
