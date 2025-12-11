import tensorflow as tf
import numpy as np
from PIL import Image
import os
import json


class ImprovedTrainedImageMalwareDetector:
    def __init__(self, model_path='models/image_malware_model.h5'):
        self.model_path = model_path
        self.model = None
        self.confidence_threshold = 0.8  # زيادة عتبة الثقة لتقليل الإيجابيات الكاذبة
        self.uncertainty_threshold = 0.25  # عتبة الشك للتصنيفات غير المؤكدة
        self.benign_threshold = 0.2  # عتبة للصور النظيفة
        self.load_trained_model()

    def load_trained_model(self):
        """تحميل النموذج المدرب مع معالجة الأخطاء"""
        try:
            if os.path.exists(self.model_path):
                self.model = tf.keras.models.load_model(self.model_path)
                print("✅ تم تحميل النموذج المدرب بنجاح!")

                # تحميل إحصائيات التدريب إذا كانت متوفرة
                stats_path = self.model_path.replace('.h5', '_stats.json')
                if os.path.exists(stats_path):
                    with open(stats_path, 'r') as f:
                        self.training_stats = json.load(f)
                        print("📊 تم تحميل إحصائيات التدريب")
                else:
                    self.training_stats = {}

            else:
                print(f"❌ لم يتم العثور على النموذج في: {self.model_path}")
                self.model = None

        except Exception as e:
            print(f"❌ خطأ في تحميل النموذج: {e}")
            self.model = None

    def preprocess_image(self, image_path, target_size=(128, 128)):
        """معالجة الصورة مع تحسينات"""
        try:
            img = Image.open(image_path)

            # تحويل إلى RGB إذا كانت الصورة شفافة أو ثنائية
            if img.mode != 'RGB':
                img = img.convert('RGB')

            img = img.resize(target_size)
            img_array = np.array(img)

            # التحقق من شكل الصورة
            if len(img_array.shape) != 3 or img_array.shape[-1] != 3:
                print(f"⚠️ شكل الصورة غير متوقع: {img_array.shape}")
                # محاولة إصلاح الشكل
                if len(img_array.shape) == 2:
                    img_array = np.stack([img_array] * 3, axis=-1)
                elif img_array.shape[-1] == 4:
                    img_array = img_array[:, :, :3]

            # تطبيع مخصص بناءً على إحصائيات التدريب
            if 'mean' in self.training_stats and 'std' in self.training_stats:
                mean = np.array(self.training_stats['mean'])
                std = np.array(self.training_stats['std'])
                img_array = (img_array - mean) / std
            else:
                # تطبيع افتراضي
                img_array = img_array / 255.0

            img_array = np.expand_dims(img_array, axis=0)
            return img_array

        except Exception as e:
            print(f"❌ خطأ في معالجة الصورة {image_path}: {e}")
            return None

    def predict_with_confidence(self, image_path):
        """التنبؤ مع حساب الثقة"""
        if self.model is None:
            print("❌ لا يوجد نموذج مدرب.")
            return 0.5, 0.0, "نموذج غير متاح"

        try:
            processed_img = self.preprocess_image(image_path)
            if processed_img is None:
                return 0.5, 0.0, "خطأ في المعالجة"

            prediction = self.model.predict(processed_img, verbose=0)[0][0]
            confidence = abs(prediction - 0.5) * 2  # حساب الثقة

            # تحسين عملية التصنيف باستخدام عتبات أكثر دقة
            if confidence < self.uncertainty_threshold:  # ثقة منخفضة جدًا
                classification = "غير مؤكد"
                final_prediction = 0.5
            elif prediction > self.confidence_threshold:
                # التحقق من هل درجة الثقة عالية بما يكفي
                if confidence > 0.7:  # درجة ثقة عالية جدًا
                    classification = "ضار"
                    final_prediction = prediction
                else:
                    classification = "مشبوه"
                    final_prediction = 0.65  # درجة مشبوهة ولكن أقل من الضارة
            elif prediction < self.benign_threshold:
                # نظيف بدرجة عالية من الثقة
                classification = "نظيف"
                final_prediction = prediction
            else:
                # منطقة وسيطة - نفترض أنها أقل إلى النظيفة
                classification = "محتمل نظيف"
                final_prediction = 0.35  # درجة منخفضة ولكن ليست صفر

            print(f"📊 التنبؤ: {prediction:.4f}, الثقة: {confidence:.4f}, التصنيف: {classification}")
            return float(final_prediction), float(confidence), classification

        except Exception as e:
            print(f"❌ خطأ في التنبؤ: {e}")
            return 0.5, 0.0, f"خطأ: {str(e)}"

    def analyze_image_features(self, image_path):
        """تحليل ميزات الصورة لفهم سبب التصنيف"""
        try:
            processed_img = self.preprocess_image(image_path)
            if processed_img is None:
                return {}

            # الحصول على تنبؤات الطبقات المخفية لفهم القرار
            feature_model = tf.keras.Model(
                inputs=self.model.input,
                outputs=[layer.output for layer in self.model.layers if 'dense' in layer.name]
            )

            layer_outputs = feature_model.predict(processed_img, verbose=0)

            feature_analysis = {
                'raw_prediction': float(self.model.predict(processed_img, verbose=0)[0][0]),
                'feature_activations': [float(np.mean(output)) for output in layer_outputs],
                'feature_std': [float(np.std(output)) for output in layer_outputs]
            }

            return feature_analysis

        except Exception as e:
            print(f"❌ خطأ في تحليل الميزات: {e}")
            return {}


# إنشاء نسخة محسنة من المحلل
improved_detector = ImprovedTrainedImageMalwareDetector()