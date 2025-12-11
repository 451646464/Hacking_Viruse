from datetime import datetime
from database import db

class Notification(db.Model):
    """نموذج الإشعارات للمستخدمين"""
    __tablename__ = 'notifications'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    title = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    notification_type = db.Column(db.String(50), default='general')  # general, security, system, admin
    icon = db.Column(db.String(50), default='bell')  # fa icon name: bell, shield, lock, etc.
    link = db.Column(db.String(255), nullable=True)  # رابط لتوجيه المستخدم عند النقر على الإشعار
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    is_global = db.Column(db.Boolean, default=False)  # إشعارات عامة لجميع المستخدمين
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # المستخدم الذي أرسل الإشعار (المدير)
    
    # العلاقات
    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('notifications', lazy=True))
    sender = db.relationship('User', foreign_keys=[sender_id], backref=db.backref('sent_notifications', lazy=True))
    
    def __repr__(self):
        return f'<Notification {self.id} for user {self.user_id}: {self.title}>'
    
    def to_dict(self):
        """تحويل الإشعار إلى قاموس للعرض في واجهة المستخدم"""
        return {
            'id': self.id,
            'title': self.title,
            'message': self.message,
            'type': self.notification_type,
            'icon': self.icon,
            'link': self.link,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'is_read': self.is_read,
            'is_global': self.is_global,
            'sender_id': self.sender_id
        }
