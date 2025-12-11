// Settings Page JavaScript - Fixed Version
console.log('Settings Fixed JS loaded');

document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM loaded - Fixed Version');
    
    // ============ TAB FUNCTIONALITY ============
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
    
    // ============ API KEY MANAGEMENT - FIXED ============
    console.log('Setting up API Key management...');
    
    const toggleApiKeyBtn = document.getElementById('toggleApiKey');
    const apiKeyDisplay = document.getElementById('apiKeyDisplay');
    const toggleIcon = document.getElementById('toggleIcon');
    const copyApiKeyBtn = document.getElementById('copyApiKey');
    const generateApiKeyBtn = document.getElementById('generateApiKey');
    const revokeApiKeyBtn = document.getElementById('revokeApiKey');
    
    console.log('API Key elements found:', {
        toggleApiKeyBtn: !!toggleApiKeyBtn,
        apiKeyDisplay: !!apiKeyDisplay,
        toggleIcon: !!toggleIcon,
        copyApiKeyBtn: !!copyApiKeyBtn,
        generateApiKeyBtn: !!generateApiKeyBtn,
        revokeApiKeyBtn: !!revokeApiKeyBtn
    });
    
    // Toggle API Key visibility - FIXED & IMPROVED
    if (toggleApiKeyBtn && apiKeyDisplay) {
        // Initialize properly - ensure correct initial state
        if (apiKeyDisplay.dataset.key && apiKeyDisplay.dataset.key !== '') {
            apiKeyDisplay.value = apiKeyDisplay.dataset.key;
        }
        
        toggleApiKeyBtn.addEventListener('click', function() {
            console.log('Toggle API Key clicked');
            
            // Get the actual key value
            const actualKey = apiKeyDisplay.dataset.key;
            const displayedValue = apiKeyDisplay.value;
            
            // Only perform toggle if we have an actual key
            if (actualKey && actualKey !== '') {
                if (apiKeyDisplay.type === 'password') {
                    // Show the key
                    apiKeyDisplay.type = 'text';
                    apiKeyDisplay.value = actualKey; // Ensure the actual key is shown
                    
                    if (toggleIcon) {
                        toggleIcon.classList.remove('fa-eye');
                        toggleIcon.classList.add('fa-eye-slash');
                    }
                    console.log('API Key shown');
                } else {
                    // Hide the key
                    apiKeyDisplay.type = 'password';
                    apiKeyDisplay.value = actualKey; // Keep actual key in value
                    
                    if (toggleIcon) {
                        toggleIcon.classList.remove('fa-eye-slash');
                        toggleIcon.classList.add('fa-eye');
                    }
                    console.log('API Key hidden');
                }
            } else {
                console.warn('No API key available to toggle');
            }
        });
    } else {
        console.error('Toggle button or API Key display not found!');
    }
    
    // Copy API Key - FIXED & IMPROVED
    if (copyApiKeyBtn && apiKeyDisplay) {
        copyApiKeyBtn.addEventListener('click', function() {
            console.log('Copy API Key clicked');
            
            // Always get from data-key attribute to ensure we get the actual value
            // regardless of whether the field is showing *** or the actual key
            const apiKey = apiKeyDisplay.dataset.key;
            
            if (apiKey && apiKey.trim() !== '' && apiKey !== 'لا يوجد مفتاح API') {
                console.log('Got API key to copy:', apiKey.substring(0, 5) + '...');
                
                // Create a temporary input element for more reliable copying
                const tempInput = document.createElement('input');
                document.body.appendChild(tempInput);
                tempInput.value = apiKey;
                tempInput.select();
                
                // Try to copy using document.execCommand first
                try {
                    const success = document.execCommand('copy');
                    if (success) {
                        showToast('تم نسخ مفتاح API بنجاح', 'success');
                        console.log('API Key copied successfully via execCommand');
                    } else {
                        // If execCommand fails, try clipboard API
                        copyWithClipboardAPI(apiKey);
                    }
                } catch (err) {
                    console.error('execCommand copy failed:', err);
                    // Fallback to clipboard API
                    copyWithClipboardAPI(apiKey);
                } finally {
                    // Clean up
                    document.body.removeChild(tempInput);
                }
            } else {
                showToast('لا يوجد مفتاح API للنسخ', 'error');
                console.log('No API key found to copy');
            }
        });
    } else {
        console.error('Copy button or API Key display not found!');
    }
    
    // Helper function for clipboard API
    function copyWithClipboardAPI(text) {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text)
                .then(() => {
                    showToast('تم نسخ مفتاح API بنجاح', 'success');
                    console.log('API Key copied successfully via Clipboard API');
                })
                .catch((err) => {
                    console.error('Clipboard API failed:', err);
                    showToast('حدث خطأ أثناء نسخ المفتاح', 'error');
                });
        } else {
            // If clipboard API is not available
            fallbackCopyToClipboard(text);
        }
    }
    
    // Fallback copy method
    function fallbackCopyToClipboard(text) {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        
        try {
            document.execCommand('copy');
            showToast('تم نسخ مفتاح API بنجاح', 'success');
            console.log('API Key copied using fallback method');
        } catch (err) {
            console.error('Fallback copy failed:', err);
            showToast('فشل نسخ مفتاح API', 'error');
        }
        
        document.body.removeChild(textArea);
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
                        if (apiKeyDisplay) {
                            apiKeyDisplay.value = data.api_key;
                            apiKeyDisplay.dataset.key = data.api_key;
                        }
                        if (copyApiKeyBtn) copyApiKeyBtn.disabled = false;
                        if (toggleApiKeyBtn) toggleApiKeyBtn.disabled = false;
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
                        if (apiKeyDisplay) {
                            apiKeyDisplay.value = 'لا يوجد مفتاح API';
                            apiKeyDisplay.dataset.key = '';
                            apiKeyDisplay.type = 'password';
                        }
                        if (copyApiKeyBtn) copyApiKeyBtn.disabled = true;
                        if (toggleApiKeyBtn) toggleApiKeyBtn.disabled = true;
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
        toast.style.cssText = `
            position: fixed;
            bottom: 20px;
            right: 20px;
            padding: 15px 20px;
            border-radius: 8px;
            color: white;
            z-index: 1000;
            opacity: 0;
            transform: translateY(20px);
            transition: all 0.3s ease;
            background-color: ${type === 'success' ? '#10B981' : '#EF4444'};
        `;
        document.body.appendChild(toast);
        
        setTimeout(() => {
            toast.style.opacity = '1';
            toast.style.transform = 'translateY(0)';
        }, 10);
        
        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateY(20px)';
            setTimeout(() => {
                if (document.body.contains(toast)) {
                    document.body.removeChild(toast);
                }
            }, 300);
        }, 3000);
    }
    
    console.log('All event listeners set up successfully!');
});
