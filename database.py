import sqlite3
import hashlib
import secrets
import datetime
from typing import Optional, List, Dict, Any
import os

class DatabaseManager:
    def __init__(self, db_path: str = "erp_system.db"):
        self.db_path = db_path
        self.init_database()
    
    def get_connection(self):
        """Get a database connection with optimizations"""
        conn = sqlite3.connect(self.db_path, timeout=20.0)  # Increase timeout
        conn.row_factory = sqlite3.Row  # Enable column access by name
        
        # Enable WAL mode for better concurrency
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=NORMAL')  # Faster than FULL
        conn.execute('PRAGMA cache_size=10000')    # Increase cache size
        conn.execute('PRAGMA temp_store=MEMORY')   # Use memory for temp tables
        
        return conn
    
    def init_database(self):
        """Initialize the database with all required tables"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                full_name VARCHAR(100) NOT NULL,
                role VARCHAR(50) DEFAULT 'Pending',
                department VARCHAR(100),
                is_active BOOLEAN DEFAULT 0,
                is_approved BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                permissions TEXT  -- JSON string for role-specific permissions
            )
        ''')
        
        # Notifications table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title VARCHAR(200) NOT NULL,
                message TEXT NOT NULL,
                type VARCHAR(50) DEFAULT 'info',
                is_read BOOLEAN DEFAULT 0,
                related_id VARCHAR(100),  -- PR/PO number
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        # System (global) notifications table - visible to all users
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                icon VARCHAR(100) NOT NULL,
                text TEXT NOT NULL,
                ref VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Feedback table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_type VARCHAR(10) NOT NULL,  -- 'PR' or 'PO'
                request_id VARCHAR(100) NOT NULL,   -- PR/PO number
                approver_id INTEGER NOT NULL,
                requester_id INTEGER NOT NULL,
                rejection_reason VARCHAR(200) NOT NULL,
                rejection_details TEXT NOT NULL,
                suggested_actions TEXT,
                status VARCHAR(20) DEFAULT 'pending',  -- pending, resolved, closed
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolved_at TIMESTAMP,
                FOREIGN KEY (approver_id) REFERENCES users (id),
                FOREIGN KEY (requester_id) REFERENCES users (id)
            )
        ''')
        
        # User sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token VARCHAR(255) UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                is_active BOOLEAN DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # User permissions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                purchase_requisition BOOLEAN DEFAULT 0,
                purchase_order BOOLEAN DEFAULT 0,
                check_status BOOLEAN DEFAULT 0,
                upload_po BOOLEAN DEFAULT 0,
                retrieve_po BOOLEAN DEFAULT 0,
                replace_amend_po BOOLEAN DEFAULT 0,
                vendor_lookup BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Create indexes for better performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(is_read)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_feedback_request ON feedback(request_type, request_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_token ON user_sessions(session_token)')
        
        # Insert default admin user if not exists
        cursor.execute('SELECT COUNT(*) FROM users WHERE role = "Admin"')
        if cursor.fetchone()[0] == 0:
            self.create_default_admin()
        
        conn.commit()
        conn.close()
    
    def create_default_admin(self):
        """Create the default admin user"""
        admin_password = os.getenv('ADMIN_PASSWORD', 'admin123')
        admin_email = os.getenv('ADMIN_EMAIL', 'admin@adventz.com')
        
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # Check if admin already exists
            cursor.execute('SELECT id FROM users WHERE role = "Admin"')
            if cursor.fetchone():
                conn.close()
                return
            
            # Create admin user directly (bypassing approval)
            password_hash = self.hash_password(admin_password)
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, full_name, role, department, is_active, is_approved)
                VALUES (?, ?, ?, ?, ?, ?, 1, 1)
            ''', ('admin', admin_email, password_hash, 'System Administrator', 'Admin', 'IT'))
            
            admin_id = cursor.lastrowid
            
            # Create admin permissions (all enabled)
            cursor.execute('''
                INSERT INTO user_permissions (user_id, purchase_requisition, purchase_order, check_status, 
                                           upload_po, retrieve_po, replace_amend_po, vendor_lookup)
                VALUES (?, 1, 1, 1, 1, 1, 1, 1)
            ''', (admin_id,))
            
            conn.commit()
            conn.close()
            print(f"Default admin user created: {admin_email}")
            
        except Exception as e:
            print(f"Error creating default admin: {e}")
    
    def hash_password(self, password: str) -> str:
        """Hash a password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def verify_password(self, password: str, password_hash: str) -> bool:
        """Verify a password against its hash"""
        return self.hash_password(password) == password_hash
    
    def create_user(self, username: str, email: str, password: str, 
                   full_name: str, role: str = 'Pending', department: str = None) -> bool:
        """Create a new user (pending approval)"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # Check if user already exists
            cursor.execute('SELECT id FROM users WHERE email = ? OR username = ?', (email, username))
            if cursor.fetchone():
                return False
            
            # Create user with hashed password (pending approval)
            password_hash = self.hash_password(password)
            
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, full_name, role, department, is_active, is_approved)
                VALUES (?, ?, ?, ?, ?, ?, 0, 0)
            ''', (username, email, password_hash, full_name, role, department))
            
            user_id = cursor.lastrowid
            
            # Create default permissions (all disabled)
            cursor.execute('''
                INSERT INTO user_permissions (user_id)
                VALUES (?)
            ''', (user_id,))
            
            # Create pending approval notification
            self.create_notification(
                user_id=user_id,
                title="Account Pending Approval",
                message=f"Your account is pending admin approval. You will be notified once approved.",
                type="pending"
            )
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"Error creating user: {e}")
            return False
    
    def authenticate_user(self, email: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate a user and return user data"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, username, email, full_name, role, department, is_active, is_approved
                FROM users WHERE email = ? AND is_active = 1 AND is_approved = 1
            ''', (email,))
            
            user = cursor.fetchone()
            if user and self.verify_password(password, self.get_password_hash(email)):
                # Update last login
                cursor.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user['id'],))
                conn.commit()
                
                # Get user permissions
                cursor.execute('SELECT * FROM user_permissions WHERE user_id = ?', (user['id'],))
                permissions = cursor.fetchone()
                
                user_dict = dict(user)
                user_dict['permissions'] = permissions if permissions else {}
                conn.close()
                return user_dict
            
            conn.close()
            return None
            
        except Exception as e:
            print(f"Error authenticating user: {e}")
            return None
    
    def get_password_hash(self, email: str) -> Optional[str]:
        """Get password hash for a user"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT password_hash FROM users WHERE email = ?', (email,))
            result = cursor.fetchone()
            conn.close()
            return result['password_hash'] if result else None
        except Exception as e:
            print(f"Error getting password hash: {e}")
            return None
    
    def get_role_permissions(self, role: str) -> str:
        """Get permissions for a specific role"""
        permissions = {
            'Admin': {
                'pr_create': True, 'pr_view': True, 'pr_edit': True, 'pr_delete': True,
                'po_create': True, 'po_view': True, 'po_edit': True, 'po_delete': True,
                'approve_pr': True, 'approve_po': True, 'dashboard_access': True,
                'user_management': True, 'system_settings': True
            },
            'PR_User': {
                'pr_create': True, 'pr_view': True, 'pr_edit': True, 'pr_delete': False,
                'po_create': False, 'po_view': True, 'po_edit': False, 'po_delete': False,
                'approve_pr': False, 'approve_po': False, 'dashboard_access': True,
                'user_management': False, 'system_settings': False
            },
            'PO_User': {
                'pr_create': False, 'pr_view': True, 'pr_edit': False, 'pr_delete': False,
                'po_create': True, 'po_view': True, 'po_edit': True, 'po_delete': False,
                'approve_pr': False, 'approve_po': False, 'dashboard_access': True,
                'user_management': False, 'system_settings': False
            },
            'Approver': {
                'pr_create': False, 'pr_view': True, 'pr_edit': False, 'pr_delete': False,
                'po_create': False, 'po_view': True, 'po_edit': False, 'po_delete': False,
                'approve_pr': True, 'approve_po': True, 'dashboard_access': True,
                'user_management': False, 'system_settings': False
            },
            'Viewer': {
                'pr_create': False, 'pr_view': True, 'pr_edit': False, 'pr_delete': False,
                'po_create': False, 'po_view': True, 'po_edit': False, 'po_delete': False,
                'approve_pr': False, 'approve_po': False, 'dashboard_access': True,
                'user_management': False, 'system_settings': False
            }
        }
        
        import json
        return json.dumps(permissions.get(role, permissions['Viewer']))
    
    def parse_permissions(self, permissions_json: str) -> Dict[str, bool]:
        """Parse permissions JSON string to dictionary"""
        try:
            import json
            return json.loads(permissions_json) if permissions_json else {}
        except:
            return {}
    
    def check_permission(self, user_id: int, permission: str) -> bool:
        """Check if a user has a specific permission"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # First check if user is admin (admin has all permissions)
            cursor.execute('SELECT role FROM users WHERE id = ?', (user_id,))
            user_result = cursor.fetchone()
            if user_result and user_result['role'] == 'Admin':
                print(f"🔓 Admin user {user_id} granted access to {permission}")
                conn.close()
                return True
            
            # For non-admin users, check specific permissions
            if permission == 'user_management':
                # Only admins can manage users
                print(f"🚫 Non-admin user {user_id} denied access to {permission}")
                conn.close()
                return False
            
            # Check other permissions from user_permissions table
            cursor.execute('SELECT * FROM user_permissions WHERE user_id = ?', (user_id,))
            permissions_result = cursor.fetchone()
            conn.close()
            
            if permissions_result:
                permissions = dict(permissions_result)
                # Map permission names to database columns
                permission_mapping = {
                    'purchase_requisition': 'purchase_requisition',
                    'purchase_order': 'purchase_order',
                    'check_status': 'check_status',
                    'upload_po': 'upload_po',
                    'retrieve_po': 'retrieve_po',
                    'replace_amend_po': 'replace_amend_po',
                    'vendor_lookup': 'vendor_lookup'
                }
                
                if permission in permission_mapping:
                    has_permission = permissions.get(permission_mapping[permission], False)
                    print(f"🔍 User {user_id} permission {permission}: {has_permission}")
                    return has_permission
            
            print(f"❌ User {user_id} has no permissions record for {permission}")
            return False
            
        except Exception as e:
            print(f"❌ Error checking permission {permission} for user {user_id}: {e}")
            return False
    
    def create_notification(self, user_id: int, title: str, message: str, 
                          type: str = 'info', related_id: str = None) -> bool:
        """Create a new notification for a user"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO notifications (user_id, title, message, type, related_id)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, title, message, type, related_id))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"Error creating notification: {e}")
            return False

    def create_system_notification(self, icon: str, text: str, ref: str = None) -> bool:
        """Create a global system notification visible to all users"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO system_notifications (icon, text, ref)
                VALUES (?, ?, ?)
            ''', (icon, text, ref))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error creating system notification: {e}")
            return False

    def get_recent_system_notifications(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get the most recent global notifications"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, icon, text, ref, created_at
                FROM system_notifications
                ORDER BY created_at DESC
                LIMIT ?
            ''', (limit,))
            rows = cursor.fetchall()
            conn.close()
            return [dict(row) for row in rows]
        except Exception as e:
            print(f"Error getting system notifications: {e}")
            return []
    
    def get_user_notifications(self, user_id: int, limit: int = 50) -> List[Dict[str, Any]]:
        """Get notifications for a specific user"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, title, message, type, is_read, related_id, created_at
                FROM notifications 
                WHERE user_id = ? 
                ORDER BY created_at DESC 
                LIMIT ?
            ''', (user_id, limit))
            
            notifications = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return notifications
            
        except Exception as e:
            print(f"Error getting notifications: {e}")
            return []
    
    def mark_notification_read(self, notification_id: int, user_id: int) -> bool:
        """Mark a notification as read"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE notifications 
                SET is_read = 1 
                WHERE id = ? AND user_id = ?
            ''', (notification_id, user_id))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"Error marking notification read: {e}")
            return False
    
    def create_feedback(self, request_type: str, request_id: str, approver_id: int,
                       requester_id: int, rejection_reason: str, rejection_details: str,
                       suggested_actions: str = None) -> bool:
        """Create feedback for a rejected request"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO feedback (request_type, request_id, approver_id, requester_id,
                                   rejection_reason, rejection_details, suggested_actions)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (request_type, request_id, approver_id, requester_id,
                  rejection_reason, rejection_details, suggested_actions))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"Error creating feedback: {e}")
            return False
    
    def get_user_feedback(self, user_id: int, request_type: str = None) -> List[Dict[str, Any]]:
        """Get feedback for a specific user"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            if request_type:
                cursor.execute('''
                    SELECT f.*, u1.full_name as approver_name, u2.full_name as requester_name
                    FROM feedback f
                    JOIN users u1 ON f.approver_id = u1.id
                    JOIN users u2 ON f.requester_id = u2.id
                    WHERE f.requester_id = ? AND f.request_type = ?
                    ORDER BY f.created_at DESC
                ''', (user_id, request_type))
            else:
                cursor.execute('''
                    SELECT f.*, u1.full_name as approver_name, u2.full_name as requester_name
                    FROM feedback f
                    JOIN users u1 ON f.approver_id = u1.id
                    JOIN users u2 ON f.requester_id = u2.id
                    WHERE f.requester_id = ?
                    ORDER BY f.created_at DESC
                ''', (user_id,))
            
            feedback = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return feedback
            
        except Exception as e:
            print(f"Error getting feedback: {e}")
            return []
    
    def create_session(self, user_id: int, expires_hours: int = 24) -> Optional[str]:
        """Create a new user session"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # Generate unique session token
            session_token = secrets.token_urlsafe(32)
            expires_at = datetime.datetime.now() + datetime.timedelta(hours=expires_hours)
            
            cursor.execute('''
                INSERT INTO user_sessions (user_id, session_token, expires_at)
                VALUES (?, ?, ?)
            ''', (user_id, session_token, expires_at))
            
            conn.commit()
            conn.close()
            return session_token
            
        except Exception as e:
            print(f"Error creating session: {e}")
            return None
    
    def validate_session(self, session_token: str) -> Optional[int]:
        """Validate a session token and return user_id if valid"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT user_id FROM user_sessions 
                WHERE session_token = ? AND expires_at > CURRENT_TIMESTAMP AND is_active = 1
            ''', (session_token,))
            
            result = cursor.fetchone()
            conn.close()
            
            return result['user_id'] if result else None
            
        except Exception as e:
            print(f"Error validating session: {e}")
            return None
    
    def invalidate_session(self, session_token: str) -> bool:
        """Invalidate a session token"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE user_sessions 
                SET is_active = 0 
                WHERE session_token = ?
            ''', (session_token,))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"Error invalidating session: {e}")
            return False
    
    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get user information by ID"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, username, email, full_name, role, department, created_at, last_login
                FROM users WHERE id = ? AND is_active = 1
            ''', (user_id,))
            
            user = cursor.fetchone()
            conn.close()
            
            return dict(user) if user else None
            
        except Exception as e:
            print(f"Error getting user: {e}")
            return None
    
    def update_user_profile(self, user_id: int, full_name: str = None, 
                           department: str = None) -> bool:
        """Update user profile information"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            updates = []
            params = []
            
            if full_name is not None:
                updates.append('full_name = ?')
                params.append(full_name)
            
            if department is not None:
                updates.append('department = ?')
                params.append(department)
            
            if not updates:
                return False
            
            params.append(user_id)
            query = f'UPDATE users SET {", ".join(updates)} WHERE id = ?'
            
            cursor.execute(query, params)
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"Error updating user profile: {e}")
            return False
    
    def change_user_password(self, user_id: int, new_password: str) -> bool:
        """Change user password"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            password_hash = self.hash_password(new_password)
            cursor.execute('UPDATE users SET password_hash = ? WHERE id = ?', (password_hash, user_id))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"Error changing password: {e}")
            return False
    
    def get_all_users(self, admin_user_id: int) -> List[Dict[str, Any]]:
        """Get all users (admin only)"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, username, email, full_name, role, department, is_active, is_approved, created_at, last_login
                FROM users ORDER BY created_at DESC
            ''')
            
            users = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return users
            
        except Exception as e:
            print(f"Error getting all users: {e}")
            return []
    
    def deactivate_user(self, user_id: int, admin_user_id: int) -> bool:
        """Deactivate a user (admin only)"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('UPDATE users SET is_active = 0 WHERE id = ?', (user_id,))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"Error deactivating user: {e}")
            return False
    
    def get_pending_users(self) -> List[Dict[str, Any]]:
        """Get users pending approval"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, username, email, full_name, department, created_at
                FROM users WHERE is_approved = 0 ORDER BY created_at DESC
            ''')
            users = cursor.fetchall()
            conn.close()
            return [dict(user) for user in users]
        except Exception as e:
            print(f"Error getting pending users: {e}")
            return []
    
    def approve_user(self, user_id: int, role: str, permissions: Dict[str, bool]) -> bool:
        """Approve a user and assign role/permissions - OPTIMIZED VERSION"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # Use a single transaction for all operations
            cursor.execute('BEGIN TRANSACTION')
            
            try:
                # Update user approval status and role
                cursor.execute('''
                    UPDATE users 
                    SET is_approved = 1, is_active = 1, role = ?
                    WHERE id = ?
                ''', (role, user_id))
                
                # Update user permissions
                cursor.execute('''
                    UPDATE user_permissions 
                    SET purchase_requisition = ?, purchase_order = ?, check_status = ?,
                        upload_po = ?, retrieve_po = ?, replace_amend_po = ?, vendor_lookup = ?
                    WHERE user_id = ?
                ''', (
                    permissions.get('purchase_requisition', False),
                    permissions.get('purchase_order', False),
                    permissions.get('check_status', False),
                    permissions.get('upload_po', False),
                    permissions.get('retrieve_po', False),
                    permissions.get('replace_amend_po', False),
                    permissions.get('vendor_lookup', False),
                    user_id
                ))
                
                # Create approval notification in the same transaction
                cursor.execute('''
                    INSERT INTO notifications (user_id, title, message, type, related_id)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    user_id, 
                    "Account Approved",
                    f"Your account has been approved by admin with role: {role}. You can now login and access the system.",
                    "approval",
                    None
                ))
                
                # Commit all changes at once
                cursor.execute('COMMIT')
                print(f"✅ User {user_id} approved successfully with role: {role}, permissions: {permissions}")
                return True
                
            except Exception as e:
                # Rollback on any error
                cursor.execute('ROLLBACK')
                raise e
                
        except Exception as e:
            print(f"❌ Error approving user {user_id}: {e}")
            return False
        finally:
            if conn:
                conn.close()
    
    def get_user_permissions(self, user_id: int) -> Dict[str, bool]:
        """Get user permissions"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute('''
                SELECT purchase_requisition, purchase_order, check_status, upload_po, 
                       retrieve_po, replace_amend_po, vendor_lookup
                FROM user_permissions WHERE user_id = ?
            ''', (user_id,))
            permissions = cursor.fetchone()
            conn.close()
            
            if permissions:
                return dict(permissions)
            return {}
            
        except Exception as e:
            print(f"Error getting user permissions: {e}")
            return {}

    def update_user_permissions(self, user_id: int, permissions: Dict[str, bool]) -> bool:
        """Update user permissions only - OPTIMIZED VERSION"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # Use transaction for consistency
            cursor.execute('BEGIN TRANSACTION')
            
            try:
                # Update user permissions
                cursor.execute('''
                    UPDATE user_permissions 
                    SET purchase_requisition = ?, purchase_order = ?, check_status = ?,
                        upload_po = ?, retrieve_po = ?, replace_amend_po = ?, vendor_lookup = ?
                    WHERE user_id = ?
                ''', (
                    permissions.get('purchase_requisition', False),
                    permissions.get('purchase_order', False),
                    permissions.get('check_status', False),
                    permissions.get('upload_po', False),
                    permissions.get('retrieve_po', False),
                    permissions.get('replace_amend_po', False),
                    permissions.get('vendor_lookup', False),
                    user_id
                ))
                
                # Create update notification in the same transaction
                cursor.execute('''
                    INSERT INTO notifications (user_id, title, message, type, related_id)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    user_id, 
                    "Permissions Updated",
                    "Your account permissions have been updated by admin.",
                    "update",
                    None
                ))
                
                # Commit all changes at once
                cursor.execute('COMMIT')
                print(f"✅ User {user_id} permissions updated successfully: {permissions}")
                return True
                
            except Exception as e:
                # Rollback on any error
                cursor.execute('ROLLBACK')
                raise e
                
        except Exception as e:
            print(f"❌ Error updating user {user_id} permissions: {e}")
            return False
        finally:
            if conn:
                conn.close()

# Global database instance
db = DatabaseManager()
