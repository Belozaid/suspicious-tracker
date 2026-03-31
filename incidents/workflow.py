#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Incident Workflow Management - Phase 5
إدارة سير عمل الحوادث (Case Management)
"""

import json
import sqlite3
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

def utc_now_iso() -> str:
    """الحصول على الوقت الحالي بصيغة ISO"""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def ensure_workflow_row(conn: sqlite3.Connection, incident_id: int) -> None:
    """التأكد من وجود سجل سير عمل للحادثة"""
    row = conn.execute(
        "SELECT incident_id FROM incident_workflow WHERE incident_id=?", 
        (incident_id,)
    ).fetchone()
    
    if row:
        return
    
    # إنشاء سجل جديد
    conn.execute(
        "INSERT INTO incident_workflow(incident_id, status, owner, notes_json, closed_reason) "
        "VALUES (?, 'OPEN', NULL, '[]', NULL)",
        (incident_id,),
    )
    conn.commit()

def add_note(conn: sqlite3.Connection, 
             incident_id: int, 
             note: str, 
             actor: str = "system") -> None:
    """إضافة ملاحظة إلى سير العمل"""
    ensure_workflow_row(conn, incident_id)
    
    # جلب الملاحظات الحالية
    row = conn.execute(
        "SELECT notes_json FROM incident_workflow WHERE incident_id=?", 
        (incident_id,)
    ).fetchone()
    
    notes = json.loads(row[0]) if row and row[0] else []
    
    # إضافة الملاحظة الجديدة
    notes.append({
        "ts_utc": utc_now_iso(), 
        "actor": actor, 
        "note": note
    })
    
    # تحديث قاعدة البيانات
    conn.execute(
        "UPDATE incident_workflow SET notes_json=?, updated_at=? WHERE incident_id=?",
        (json.dumps(notes, ensure_ascii=False), utc_now_iso(), incident_id)
    )
    conn.commit()

def set_status(conn: sqlite3.Connection, 
               incident_id: int, 
               status: str, 
               reason: Optional[str] = None) -> None:
    """تحديث حالة الحادثة"""
    ensure_workflow_row(conn, incident_id)
    
    # التحقق من صحة الحالة
    valid_statuses = ['OPEN', 'TRIAGED', 'INVESTIGATING', 'CLOSED']
    if status not in valid_statuses:
        raise ValueError(f"Invalid status: {status}. Must be one of {valid_statuses}")
    
    conn.execute(
        "UPDATE incident_workflow SET status=?, closed_reason=?, updated_at=? WHERE incident_id=?",
        (status, reason, utc_now_iso(), incident_id),
    )
    conn.commit()
    
    # تحديث جدول incidents الأصلي أيضاً
    conn.execute(
        "UPDATE incidents SET status=?, last_update_time=? WHERE id=?",
        (status, utc_now_iso(), incident_id)
    )
    conn.commit()

def assign_owner(conn: sqlite3.Connection, incident_id: int, owner: str) -> None:
    """تعيين مالك للحادثة"""
    ensure_workflow_row(conn, incident_id)
    conn.execute(
        "UPDATE incident_workflow SET owner=?, updated_at=? WHERE incident_id=?",
        (owner, utc_now_iso(), incident_id)
    )
    conn.commit()

def get_workflow(conn: sqlite3.Connection, incident_id: int) -> Dict[str, Any]:
    """الحصول على بيانات سير العمل"""
    ensure_workflow_row(conn, incident_id)
    
    row = conn.execute(
        "SELECT status, owner, notes_json, closed_reason FROM incident_workflow WHERE incident_id=?",
        (incident_id,),
    ).fetchone()
    
    notes = []
    if row and row[2]:
        try:
            notes = json.loads(row[2])
        except Exception:
            notes = []
    
    return {
        "status": row[0] if row else "OPEN",
        "owner": row[1] if row else None,
        "notes": notes,
        "closed_reason": row[3] if row else None,
    }

def close_incident(conn: sqlite3.Connection, 
                   incident_id: int, 
                   reason: str,
                   actor: str = "system") -> None:
    """إغلاق الحادثة مع سبب"""
    set_status(conn, incident_id, "CLOSED", reason)
    add_note(conn, incident_id, f"Incident closed. Reason: {reason}", actor)