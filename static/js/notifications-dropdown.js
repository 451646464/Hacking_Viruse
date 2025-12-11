// كود تحميل الإشعارات في القائمة المنسدلة
document.addEventListener('DOMContentLoaded', function() {
    const notificationsDropdown = document.getElementById('notifications-dropdown');
    
    if (!notificationsDropdown) return;
    
    // تحميل الإشعارات
    function loadNotifications() {
        fetch('/api/notifications?limit=5&unread=true')
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    renderNotifications(data.notifications);
                    updateNotificationCount(data.unread_count);
                } else {
                    notificationsDropdown.innerHTML = '<div class="text-center py-4"><div class="text-gray-400">حدث خطأ أثناء تحميل الإشعارات</div></div>';
                }
            })
            .catch(error => {
                console.error('Error:', error);
                notificationsDropdown.innerHTML = '<div class="text-center py-4"><div class="text-gray-400">حدث خطأ أثناء الاتصال بالخادم</div></div>';
            });
    }
    
    // عرض الإشعارات
    function renderNotifications(notifications) {
        if (notifications.length === 0) {
            notificationsDropdown.innerHTML = '<div class="text-center py-4"><div class="text-gray-400">لا توجد إشعارات جديدة</div></div>';
            return;
        }
        
        notificationsDropdown.innerHTML = '';
        
        notifications.forEach(notification => {
            const notificationElement = document.createElement('div');
            notificationElement.className = 'px-4 py-3 border-b border-gray-700 hover:bg-gray-700/50 transition-colors cursor-pointer';
            notificationElement.dataset.id = notification.id;
            
            // تحديد لون الأيقونة حسب النوع
            let iconClass = 'text-blue-400';
            if (notification.type === 'security') iconClass = 'text-green-400';
            if (notification.type === 'admin') iconClass = 'text-purple-400';
            if (notification.type === 'system') iconClass = 'text-yellow-400';
            if (notification.type === 'warning') iconClass = 'text-orange-400';
            
            notificationElement.innerHTML = `
                <div class="flex">
                    <div class="text-xl ${iconClass} mr-3">
                        <i class="fas fa-${notification.icon || 'bell'}"></i>
                    </div>
                    <div class="flex-1 relative">
                        <div class="font-medium text-white">${notification.title}</div>
                        <p class="text-gray-400 text-sm line-clamp-2">${notification.message}</p>
                        <div class="text-gray-500 text-xs mt-1">${formatTime(notification.created_at)}</div>
                    </div>
                    ${!notification.is_read ? '<div class="w-2 h-2 bg-blue-500 rounded-full absolute top-2 left-0"></div>' : ''}
                </div>
            `;
            
            // إضافة حدث النقر
            notificationElement.addEventListener('click', function() {
                markAsRead(notification.id);
                
                // إذا كان هناك رابط، انتقل إليه
                if (notification.link) {
                    window.location.href = notification.link;
                } else {
                    window.location.href = '/notifications';
                }
            });
            
            notificationsDropdown.appendChild(notificationElement);
        });
    }
    
    // تحديث عدد الإشعارات غير المقروءة
    function updateNotificationCount(count) {
        const countBadges = document.querySelectorAll('.notification-count');
        countBadges.forEach(badge => {
            if (count > 0) {
                badge.textContent = count;
                badge.classList.remove('hidden');
            } else {
                badge.classList.add('hidden');
            }
        });
    }
    
    // تحديد إشعار كمقروء
    function markAsRead(id) {
        fetch(`/api/notifications/${id}/read`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // سيتم تحديث الإشعارات عند الانتقال إلى صفحة جديدة
            }
        })
        .catch(error => {
            console.error('Error:', error);
        });
    }
    
    // تنسيق الوقت
    function formatTime(dateStr) {
        const date = new Date(dateStr);
        const now = new Date();
        const diff = Math.floor((now - date) / 1000);
        
        if (diff < 60) {
            return 'منذ أقل من دقيقة';
        } else if (diff < 3600) {
            const minutes = Math.floor(diff / 60);
            return `منذ ${minutes} دقيقة${minutes > 10 ? '' : ''}`;
        } else if (diff < 86400) {
            const hours = Math.floor(diff / 3600);
            return `منذ ${hours} ساعة${hours > 10 ? '' : ''}`;
        } else {
            const days = Math.floor(diff / 86400);
            if (days < 7) {
                return `منذ ${days} يوم${days > 10 ? '' : ''}`;
            } else {
                return date.toLocaleDateString('ar-SA');
            }
        }
    }
    
    // تحميل الإشعارات عند فتح القائمة المنسدلة
    const notificationBell = document.querySelector('.fa-bell').parentElement;
    notificationBell.addEventListener('mouseenter', function() {
        loadNotifications();
    });
    
    // تحديث الإشعارات كل دقيقة إذا كانت القائمة مفتوحة
    setInterval(function() {
        const dropdown = notificationBell.parentElement.querySelector('.group-hover\\:block');
        if (dropdown && !dropdown.classList.contains('hidden')) {
            loadNotifications();
        }
    }, 60000);
    
    // تحميل الإشعارات عند تحميل الصفحة
    loadNotifications();
});
