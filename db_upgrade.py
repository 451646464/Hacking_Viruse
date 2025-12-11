from app import app, db
from models import Notification
import logging

def upgrade_database():
    """تحديث قاعدة البيانات بإنشاء جداول جديدة مثل جدول الإشعارات"""
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    with app.app_context():
        try:
            logger.info("بدء تحديث قاعدة البيانات...")
            # إنشاء الجداول الجديدة فقط إذا لم تكن موجودة
            db.create_all()
            logger.info("تم تحديث قاعدة البيانات بنجاح")
            
            # طباعة جميع الجداول الموجودة للتأكد
            tables = db.engine.table_names()
            logger.info(f"الجداول الموجودة في قاعدة البيانات: {', '.join(tables)}")
            
            return True
        except Exception as e:
            logger.error(f"حدث خطأ أثناء تحديث قاعدة البيانات: {str(e)}")
            return False

if __name__ == '__main__':
    upgrade_database()
