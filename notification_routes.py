from flask import Blueprint, request, jsonify, render_template
from flask_login import login_required, current_user
from models import User, Notification, db
from notifications import (
    get_user_notifications, mark_notification_read,
    mark_all_read, delete_notification, count_unread_notifications,
    create_notification, create_global_notification
)
from functools import wraps

# إنشاء blueprint للإشعارات
notifications_bp = Blueprint('notifications', __name__)

# decorator للتحقق من أن المستخدم مدير
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return jsonify({'success': False, 'message': 'غير مصرح لك بهذا الإجراء'}), 403
        return f(*args, **kwargs)
    return decorated_function

@notifications_bp.route('/notifications')
@login_required
def notifications_page():
    """عرض صفحة الإشعارات الرئيسية"""
    notifications = get_user_notifications(current_user.id)
    return render_template('notifications.html', notifications=notifications)

@notifications_bp.route('/api/notifications')
@login_required
def get_notifications():
    """الحصول على إشعارات المستخدم الحالي كـ JSON"""
    unread_only = request.args.get('unread', '').lower() == 'true'
    limit = int(request.args.get('limit', 20))
    
    notifications = get_user_notifications(current_user.id, unread_only, limit)
    return jsonify({
        'success': True,
        'notifications': [n.to_dict() for n in notifications],
        'unread_count': count_unread_notifications(current_user.id)
    })

@notifications_bp.route('/api/notifications/count')
@login_required
def get_notifications_count():
    """عدد الإشعارات غير المقروءة"""
    count = count_unread_notifications(current_user.id)
    return jsonify({'success': True, 'count': count})

@notifications_bp.route('/api/notifications/<int:notification_id>/read', methods=['POST'])
@login_required
def mark_read(notification_id):
    """تحديد إشعار كمقروء"""
    success = mark_notification_read(notification_id, current_user.id)
    return jsonify({'success': success})

@notifications_bp.route('/api/notifications/read/all', methods=['POST'])
@login_required
def mark_all_notifications_read():
    """تحديد جميع الإشعارات كمقروءة"""
    count = mark_all_read(current_user.id)
    return jsonify({'success': True, 'count': count})

@notifications_bp.route('/api/notifications/<int:notification_id>', methods=['DELETE'])
@login_required
def delete_single_notification(notification_id):
    """حذف إشعار"""
    success = delete_notification(notification_id, None if current_user.is_admin else current_user.id)
    return jsonify({'success': success})

# مسارات إدارة الإشعارات (للمدير فقط)
@notifications_bp.route('/admin/notifications')
@login_required
@admin_required
def admin_notifications_page():
    """صفحة إدارة الإشعارات للمدير"""
    # الحصول على جميع المستخدمين للاختيار من بينهم
    users = User.query.all()
    return render_template('admin/notifications.html', users=users)

@notifications_bp.route('/api/admin/notifications/sent')
@login_required
@admin_required
def get_sent_notifications():
    """الحصول على الإشعارات المرسلة من المدير"""
    # الحصول على جميع الإشعارات التي أرسلها المدير
    notifications = Notification.query.filter_by(sender_id=current_user.id).order_by(Notification.created_at.desc()).all()
    return jsonify({
        'success': True,
        'notifications': [n.to_dict() for n in notifications]
    })

@notifications_bp.route('/api/admin/notifications/<int:notification_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_admin_notification(notification_id):
    """حذف إشعار من قبل المدير"""
    # التحقق من أن المدير هو من أرسل هذا الإشعار
    notification = Notification.query.filter_by(id=notification_id, sender_id=current_user.id).first()
    
    if not notification:
        return jsonify({'success': False, 'message': 'لم يتم العثور على الإشعار'}), 404
    
    db.session.delete(notification)
    db.session.commit()
    
    return jsonify({'success': True})

@notifications_bp.route('/api/admin/notifications/create', methods=['POST'])
@login_required
@admin_required
def create_new_notification():
    """إنشاء إشعار جديد (للمدير فقط)"""
    data = request.json
    
    if not data:
        return jsonify({'success': False, 'message': 'لم يتم توفير بيانات الإشعار'}), 400
    
    title = data.get('title')
    message = data.get('message')
    
    if not title or not message:
        return jsonify({'success': False, 'message': 'يجب توفير العنوان والرسالة'}), 400
    
    notification_type = data.get('type', 'general')
    icon = data.get('icon', 'bell')
    link = data.get('link')
    is_global = data.get('is_global', False)
    user_id = data.get('user_id')
    
    # إذا كان الإشعار عاماً، فلا يتم تحديد مستخدم معين
    if is_global:
        notification = create_global_notification(
            title=title,
            message=message,
            notification_type=notification_type,
            icon=icon,
            link=link,
            sender_id=current_user.id
        )
    else:
        # التحقق من وجود المستخدم
        if not user_id:
            return jsonify({'success': False, 'message': 'يجب تحديد مستخدم'}), 400
        
        notification = create_notification(
            user_id=user_id,
            title=title,
            message=message,
            notification_type=notification_type,
            icon=icon,
            link=link,
            is_global=False,
            sender_id=current_user.id
        )
    
    return jsonify({
        'success': True,
        'message': 'تم إنشاء الإشعار بنجاح',
        'notification': notification.to_dict()
    })
