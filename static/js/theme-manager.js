/**
 * نظام إدارة المظاهر - يمكن تغيير المظهر من داكن إلى فاتح وتلقائي
 */

// تعريف الوظيفة الرئيسية للتحكم بالمظاهر
class ThemeManager {
    constructor() {
        // القيم المتاحة للمظاهر
        this.THEMES = {
            DARK: 'dark',
            LIGHT: 'light',
            SYSTEM: 'system'
        };
        
        // اسم المظهر في التخزين المحلي
        this.STORAGE_KEY = 'app-theme';
        
        // معرفة المظهر المتاح على النظام
        this.systemTheme = this.getSystemTheme();
        
        // استمع للتغيرات في مظهر النظام
        this.setupSystemThemeListener();
        
        // تطبيق المظهر المحفوظ عند التحميل
        this.applyStoredTheme();
    }
    
    // الحصول على المظهر من التخزين المحلي أو استخدام الافتراضي
    getStoredTheme() {
        return localStorage.getItem(this.STORAGE_KEY) || this.THEMES.DARK;
    }
    
    // حفظ المظهر في التخزين المحلي
    saveTheme(theme) {
        localStorage.setItem(this.STORAGE_KEY, theme);
    }
    
    // تغيير المظهر الحالي
    setTheme(theme) {
        console.log(`تغيير المظهر إلى: ${theme}`);
        
        // حفظ في التخزين المحلي
        this.saveTheme(theme);
        
        // تطبيق المظهر
        this.applyTheme(theme);
        
        // تحديث أزرار المظاهر إن وجدت
        this.updateThemeButtons(theme);
    }
    
    // الحصول على مظهر النظام (داكن أو فاتح)
    getSystemTheme() {
        return window.matchMedia('(prefers-color-scheme: dark)').matches ? 
            this.THEMES.DARK : this.THEMES.LIGHT;
    }
    
    // الاستماع لتغيرات مظهر النظام
    setupSystemThemeListener() {
        window.matchMedia('(prefers-color-scheme: dark)')
            .addEventListener('change', (e) => {
                this.systemTheme = e.matches ? this.THEMES.DARK : this.THEMES.LIGHT;
                
                // إذا كان المظهر معين على "تلقائي"، طبق مظهر النظام الجديد
                if (this.getStoredTheme() === this.THEMES.SYSTEM) {
                    this.applyTheme(this.THEMES.SYSTEM);
                }
            });
    }
    
    // تطبيق المظهر المحفوظ
    applyStoredTheme() {
        const storedTheme = this.getStoredTheme();
        this.applyTheme(storedTheme);
        this.updateThemeButtons(storedTheme);
    }
    
    // تطبيق المظهر المحدد
    applyTheme(theme) {
        const root = document.documentElement;
        const body = document.body;
        
        // تنظيف كل الكلاسات المتعلقة بالمظهر
        root.classList.remove('dark-mode', 'light-mode');
        body.classList.remove('dark-mode', 'light-mode');
        
        // تحديد المظهر الذي سيتم تطبيقه
        let appliedTheme = theme;
        
        // إذا كان المظهر "تلقائي"، استخدم مظهر النظام
        if (theme === this.THEMES.SYSTEM) {
            appliedTheme = this.systemTheme;
        }
        
        // تطبيق الكلاس المناسب
        if (appliedTheme === this.THEMES.LIGHT) {
            root.classList.add('light-mode');
            body.classList.add('light-mode');
            document.querySelector('meta[name="color-scheme"]')?.setAttribute('content', 'light');
        } else {
            // إذا كان داكناً، لا نحتاج لإضافة كلاسات لأن الداكن هو الافتراضي
            document.querySelector('meta[name="color-scheme"]')?.setAttribute('content', 'dark');
        }
        
        // إرسال حدث لإعلام باقي أجزاء التطبيق بتغير المظهر
        window.dispatchEvent(new CustomEvent('theme-changed', { 
            detail: { theme: appliedTheme } 
        }));
    }
    
    // تحديث أزرار تغيير المظهر
    updateThemeButtons(activeTheme) {
        // تحديث حالة أزرار الراديو في صفحة الإعدادات
        const themeRadios = document.querySelectorAll('input[name="theme"]');
        themeRadios.forEach(radio => {
            if (radio.value === activeTheme) {
                radio.checked = true;
            }
        });
    }
}

// إنشاء وتصدير مدير المظاهر
const themeManager = new ThemeManager();

// إضافة مستمع أحداث لتغير المظهر من خلال أزرار الراديو
document.addEventListener('DOMContentLoaded', function() {
    const themeRadios = document.querySelectorAll('input[name="theme"]');
    themeRadios.forEach(radio => {
        radio.addEventListener('change', function() {
            if (this.checked) {
                themeManager.setTheme(this.value);
            }
        });
    });
    
    // إضافة أيقونة المظهر في القائمة العلوية
    const navEnd = document.querySelector('.flex.items-center.space-x-6 .hidden.md\\:flex');
    if (navEnd) {
        const themeToggle = document.createElement('div');
        themeToggle.className = 'relative group';
        themeToggle.innerHTML = `
            <button id="themeToggleBtn" class="text-gray-300 hover:text-white flex items-center">
                <i id="themeIcon" class="fas fa-moon text-xl"></i>
            </button>
            <div class="absolute right-0 mt-2 w-48 bg-gray-800 rounded-lg shadow-xl py-2 z-50 hidden group-hover:block">
                <a href="#" class="theme-option block px-4 py-2 hover:bg-gray-700" data-theme="dark">
                    <i class="fas fa-moon mr-2"></i> المظهر الداكن
                </a>
                <a href="#" class="theme-option block px-4 py-2 hover:bg-gray-700" data-theme="light">
                    <i class="fas fa-sun mr-2"></i> المظهر الفاتح
                </a>
                <a href="#" class="theme-option block px-4 py-2 hover:bg-gray-700" data-theme="system">
                    <i class="fas fa-laptop mr-2"></i> المظهر التلقائي
                </a>
            </div>
        `;
        navEnd.insertBefore(themeToggle, navEnd.firstChild);
        
        // إضافة الوظيفة للزر
        const themeOptions = document.querySelectorAll('.theme-option');
        themeOptions.forEach(option => {
            option.addEventListener('click', function(e) {
                e.preventDefault();
                const selectedTheme = this.getAttribute('data-theme');
                themeManager.setTheme(selectedTheme);
            });
        });
        
        // تحديث أيقونة المظهر عند التحميل
        updateThemeIcon();
    }
    
    // استماع لتغيرات المظهر لتحديث الأيقونة
    window.addEventListener('theme-changed', function(e) {
        updateThemeIcon(e.detail.theme);
    });
    
    function updateThemeIcon(theme) {
        const currentTheme = theme || themeManager.getStoredTheme();
        const appliedTheme = currentTheme === 'system' ? themeManager.systemTheme : currentTheme;
        const themeIcon = document.getElementById('themeIcon');
        
        if (themeIcon) {
            themeIcon.className = appliedTheme === 'light' ? 
                'fas fa-sun text-xl text-yellow-400' : 
                'fas fa-moon text-xl text-blue-400';
        }
    }
});

// تصدير مدير المظاهر للاستخدام في أماكن أخرى
window.themeManager = themeManager;
