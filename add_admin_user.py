from app import app
from database import db
from models import User, UserSettings
from werkzeug.security import generate_password_hash
from datetime import datetime

def create_admin_user():
    """إنشاء مستخدم بصلاحيات المدير"""
    with app.app_context():
        # التحقق مما إذا كان المستخدم موجود بالفعل
        existing_user = User.query.filter_by(username='admin').first()
        if existing_user:
            print("المستخدم 'admin' موجود بالفعل!")
            return
            
        # إنشاء مستخدم جديد
        admin_user = User(
            username='admin',
            email='admin@example.com',
            password=generate_password_hash('admin'),
            is_admin=True,
            is_verified=True,
            created_at=datetime.utcnow(),
            profile_image='default.png'
        )
        
        db.session.add(admin_user)
        db.session.commit()
        
        # إنشاء إعدادات المستخدم
        admin_settings = UserSettings(
            user_id=admin_user.id,
            language='ar',
            theme='dark',
            security_notifications=True
        )
        
        db.session.add(admin_settings)
        db.session.commit()
        
        print("✅ تم إنشاء مستخدم المدير بنجاح!")
        print("اسم المستخدم: admin")
        print("كلمة المرور: admin")

if __name__ == "__main__":
    create_admin_user()
