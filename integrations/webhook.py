# integrations/webhook.py
import json
import urllib.request
import urllib.error
import logging

logger = logging.getLogger(__name__)

def post_webhook(url: str, payload: dict, timeout: int = 5) -> int:
    """
    إرسال الحمولة (payload) إلى Webhook URL محدد.
    تعيد رمز حالة HTTP.
    """
    if not url:
        logger.warning("محاولة إرسال Webhook بدون عنوان URL.")
        return 0

    try:
        data = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.getcode()
            logger.info(f"تم إرسال Webhook بنجاح إلى {url}. رمز الحالة: {status}")
            return status
    except urllib.error.HTTPError as e:
        logger.error(f"خطأ HTTP أثناء إرسال Webhook: {e.code} - {e.reason}")
        return e.code
    except urllib.error.URLError as e:
        logger.error(f"خطأ في عنوان URL للـ Webhook: {e.reason}")
        return -1
    except Exception as e:
        logger.exception(f"خطأ غير متوقع أثناء إرسال Webhook: {e}")
        return -2