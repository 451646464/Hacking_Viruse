from flask import jsonify, render_template
from flask_login import current_user
from models import Notification, User, db
from datetime import datetime
from sqlalchemy import or_, and_

def create_notification(user_id, title, message, notification_type='general', icon='bell', link=None, is_global=False, sender_id=None):
    """
    إنشاء إشعار جديد
    
    Args:
        user_id: معرف المستخدم (None إذا كان الإشعار عاماً)
        title: عنوان الإشعار
        message: نص الإشعار
        notification_type: نوع الإشعار (general, security, system, admin)
        icon: أيقونة من Font Awesome
        link: رابط اختياري للتوجيه عند النقر
        is_global: إذا كان الإشعار عاماً لجميع المستخدمين
        sender_id: معرف المرسل (المدير)
        
    Returns:
        Notification: كائن الإشعار الجديد
    """
    notification = Notification(
        user_id=user_id,
        title=title,
        message=message,
        notification_type=notification_type,
        icon=icon,
        link=link,
        is_global=is_global,
        sender_id=sender_id
    )
    
    db.session.add(notification)
    db.session.commit()
    return notification

def create_global_notification(title, message, notification_type='general', icon='bell', link=None, sender_id=None):
    """
    إنشاء إشعار عام لجميع المستخدمين
    """
    return create_notification(
        user_id=None,
        title=title,
        message=message,
        notification_type=notification_type,
        icon=icon,
        link=link,
        is_global=True,
        sender_id=sender_id
    )

def get_user_notifications(user_id, unread_only=False, limit=20):
    """
    الحصول على إشعارات المستخدم
    """
    query = Notification.query.filter(
        or_(
            Notification.user_id == user_id,
            and_(Notification.is_global == True, Notification.user_id == None)
        )
    ).order_by(Notification.created_at.desc())
    
    if unread_only:
        query = query.filter_by(is_read=False)
    
    return query.limit(limit).all()

def count_unread_notifications(user_id):
    """
    عد الإشعارات غير المقروءة
    """
    return Notification.query.filter(
        or_(
            Notification.user_id == user_id,
            and_(Notification.is_global == True, Notification.user_id == None)
        ),
        Notification.is_read == False
    ).count()

def mark_notification_read(notification_id, user_id=None):
    """
    تحديد إشعار كمقروء
    """
    notification = Notification.query.get(notification_id)
    if not notification:
        return False
    
    # تحقق من أن الإشعار ينتمي للمستخدم أو أنه إشعار عام
    if notification.is_global or (user_id and notification.user_id == user_id):
        notification.is_read = True
        db.session.commit()
        return True
    
    return False

def mark_all_read(user_id):
    """
    تحديد جميع إشعارات المستخدم كمقروءة
    """
    notifications = Notification.query.filter(
        or_(
            Notification.user_id == user_id,
            and_(Notification.is_global == True, Notification.user_id == None)
        ),
        Notification.is_read == False
    ).all()
    
    for notification in notifications:
        notification.is_read = True
    
    db.session.commit()
    return len(notifications)

def delete_notification(notification_id, user_id=None):
    """
    حذف إشعار
    """
    notification = Notification.query.get(notification_id)
    if not notification:
        return False
    
    # تحقق من أن الإشعار ينتمي للمستخدم أو المستخدم هو مدير
    if user_id is None or notification.user_id == user_id or notification.is_global:
        db.session.delete(notification)
        db.session.commit()
        return True
    
    return False

def render_notification_html(notification):
    """
    إنشاء HTML للإشعار للعرض في القائمة المنسدلة
    """
    return render_template('partials/notification_item.html', notification=notification)

def get_notification_icon_class(notification_type):
    """
    تحديد صنف الأيقونة بناءً على نوع الإشعار
    """
    icon_map = {
        'general': 'bell',
        'security': 'shield-alt',
        'system': 'cog',
        'admin': 'user-shield',
        'warning': 'exclamation-triangle',
        'success': 'check-circle',
        'info': 'info-circle'
    }
    return icon_map.get(notification_type, 'bell')
