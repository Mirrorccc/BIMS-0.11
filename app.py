from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_cors import CORS
import mysql.connector
import jwt
from datetime import datetime, timedelta
from functools import wraps
import hashlib
import os
import secrets  # 导入secrets模块用于生成安全的随机密钥
import uuid  # 导入uuid模块用于生成文件名
import werkzeug.utils  # 导入werkzeug用于安全文件名处理

app = Flask(__name__)
# 修改CORS配置，支持cookie
CORS(app, supports_credentials=True)
# 每次启动应用时生成新的session密钥，这样之前的session将无效
app.secret_key = secrets.token_hex(16)  # 生成32字符的随机十六进制字符串
# 设置session的生命周期
app.permanent_session_lifetime = timedelta(hours=24)

# 设置上传文件保存路径
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/uploads')
# 确保上传目录存在
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
# 允许上传的文件类型
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
# 设置最大上传文件大小为 5MB
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024

# 数据库配置
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '032236',
    'database': 'boiler_system'
}

# JWT密钥
SECRET_KEY = 'your-secret-key'

# 数据库连接辅助函数
def get_db_connection():
    return mysql.connector.connect(**db_config)

# 执行数据库操作的辅助函数
def execute_db_query(query, params=None, fetch_one=False, commit=False):
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(query, params or ())
        
        if fetch_one:
            result = cursor.fetchone()
        elif not commit:
            result = cursor.fetchall()
        else:
            conn.commit()
            result = None
            
        return result
    except Exception as e:
        if conn and commit:
            conn.rollback()
        raise e
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': '缺少认证令牌'}), 401
        try:
            # 从 Bearer token 中提取token
            token = token.split(' ')[1]
            # 解码token并验证权限
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            # 将用户信息添加到请求中
            request.user = payload
        except:
            return jsonify({'message': '无效的认证令牌'}), 401
        return f(*args, **kwargs)
    return decorated

# 添加检查用户是否已登录的装饰器
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def index():
    # 如果用户已登录，直接重定向到仪表板
    if 'user_id' in session:
        print(f"用户已登录: {session['username']}")  # 添加调试信息
        return redirect(url_for('dashboard'))
    print("没有用户登录，显示登录页面")  # 添加调试信息
    return render_template('login.html')

@app.route('/dashboard')
@login_required  # 添加登录检查
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # 计算密码的SHA256哈希值
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    try:
        # 查询用户（使用password_hash字段）并获取角色信息
        query = '''
            SELECT u.user_id, u.username, r.role_name, r.role_id,
                   r.can_edit_personnel, r.can_manage_device, r.can_view_reports
            FROM users u 
            JOIN roles r ON u.role_id = r.role_id 
            WHERE u.username = %s AND u.password_hash = %s
        '''
        user = execute_db_query(query, (username, password_hash), fetch_one=True)
        
        if user:
            # 生成JWT token
            token = jwt.encode({
                'user_id': user['user_id'],
                'username': user['username'],
                'role': user['role_name'],
                'permissions': {
                    'can_edit_personnel': bool(user['can_edit_personnel']),
                    'can_manage_device': bool(user['can_manage_device']),
                    'can_view_reports': bool(user['can_view_reports'])
                },
                'exp': datetime.utcnow() + timedelta(hours=24)
            }, SECRET_KEY, algorithm='HS256')
            
            # 将用户信息存储在session中
            session.clear()  # 清除之前的session数据
            session['user_id'] = user['user_id']
            session['username'] = user['username']
            session['role'] = user['role_name']
            session['permissions'] = {
                'can_edit_personnel': bool(user['can_edit_personnel']),
                'can_manage_device': bool(user['can_manage_device']),
                'can_view_reports': bool(user['can_view_reports'])
            }
            session.permanent = True  # 使session持久化
            
            return jsonify({
                'status': 'success',
                'token': token,
                'user': {
                    'id': user['user_id'],
                    'username': user['username'],
                    'role': user['role_name'],
                    'permissions': {
                        'can_edit_personnel': bool(user['can_edit_personnel']),
                        'can_manage_device': bool(user['can_manage_device']),
                        'can_view_reports': bool(user['can_view_reports'])
                    }
                }
            })
        else:
            # 登录失败，清除session
            session.clear()
            return jsonify({'status': 'error', 'message': '用户名或密码错误'}), 401
            
    except Exception as e:
        # 发生错误，清除session
        session.clear()
        return jsonify({'status': 'error', 'message': str(e)}), 500

# 添加登出路由
@app.route('/api/logout', methods=['POST'])
def logout():
    # 清除session中的用户信息
    session.clear()
    return jsonify({'status': 'success', 'message': '已成功登出'})

# 获取所有人员信息
@app.route('/api/personnel', methods=['GET'])
@token_required
def get_personnel():
    # 检查权限
    if not request.user.get('permissions', {}).get('can_edit_personnel'):
        return jsonify({'message': '没有权限访问此资源'}), 403

    try:
        personnel = execute_db_query('SELECT * FROM personnel ORDER BY create_time DESC')
        return jsonify(personnel)
    except Exception as e:
        return jsonify({'message': str(e)}), 500

# 获取单个人员信息
@app.route('/api/personnel/<employee_id>', methods=['GET'])
@token_required
def get_personnel_by_id(employee_id):
    if not request.user.get('permissions', {}).get('can_edit_personnel'):
        return jsonify({'message': '没有权限访问此资源'}), 403

    try:
        person = execute_db_query('SELECT * FROM personnel WHERE employee_id = %s', (employee_id,), fetch_one=True)
        
        if person:
            return jsonify(person)
        else:
            return jsonify({'message': '未找到该人员'}), 404
    except Exception as e:
        return jsonify({'message': str(e)}), 500

# 添加人员
@app.route('/api/personnel', methods=['POST'])
@token_required
def add_personnel():
    if not request.user.get('permissions', {}).get('can_edit_personnel'):
        return jsonify({'message': '没有权限访问此资源'}), 403

    data = request.get_json()
    required_fields = ['employee_id', 'name', 'department', 'position']
    
    # 验证必填字段
    for field in required_fields:
        if not data.get(field):
            return jsonify({'message': f'缺少必填字段: {field}'}), 400

    try:
        # 检查工号是否已存在
        exists = execute_db_query('SELECT employee_id FROM personnel WHERE employee_id = %s', 
                                 (data['employee_id'],), fetch_one=True)
        if exists:
            return jsonify({'message': '工号已存在'}), 400

        # 插入新人员记录
        sql = '''
            INSERT INTO personnel (employee_id, name, department, position, contact_phone, email)
            VALUES (%s, %s, %s, %s, %s, %s)
        '''
        values = (
            data['employee_id'],
            data['name'],
            data['department'],
            data['position'],
            data.get('contact_phone'),
            data.get('email')
        )
        
        execute_db_query(sql, values, commit=True)
        
        return jsonify({'message': '添加成功'}), 201
    except Exception as e:
        return jsonify({'message': str(e)}), 500

# 更新人员信息
@app.route('/api/personnel/<employee_id>', methods=['PUT'])
@token_required
def update_personnel(employee_id):
    if not request.user.get('permissions', {}).get('can_edit_personnel'):
        return jsonify({'message': '没有权限访问此资源'}), 403

    data = request.get_json()
    required_fields = ['name', 'department', 'position']
    
    # 验证必填字段
    for field in required_fields:
        if not data.get(field):
            return jsonify({'message': f'缺少必填字段: {field}'}), 400

    try:
        # 检查人员是否存在
        exists = execute_db_query('SELECT employee_id FROM personnel WHERE employee_id = %s', 
                                 (employee_id,), fetch_one=True)
        if not exists:
            return jsonify({'message': '未找到该人员'}), 404

        # 更新人员信息
        sql = '''
            UPDATE personnel 
            SET name = %s, department = %s, position = %s, contact_phone = %s, email = %s
            WHERE employee_id = %s
        '''
        values = (
            data['name'],
            data['department'],
            data['position'],
            data.get('contact_phone'),
            data.get('email'),
            employee_id
        )
        
        execute_db_query(sql, values, commit=True)
        
        return jsonify({'message': '更新成功'})
    except Exception as e:
        return jsonify({'message': str(e)}), 500

# 删除人员
@app.route('/api/personnel/<employee_id>', methods=['DELETE'])
@token_required
def delete_personnel(employee_id):
    if not request.user.get('permissions', {}).get('can_edit_personnel'):
        return jsonify({'message': '没有权限访问此资源'}), 403

    try:
        # 检查人员是否存在
        exists = execute_db_query('SELECT employee_id FROM personnel WHERE employee_id = %s', 
                                 (employee_id,), fetch_one=True)
        if not exists:
            return jsonify({'message': '未找到该人员'}), 404

        # 删除人员记录
        execute_db_query('DELETE FROM personnel WHERE employee_id = %s', (employee_id,), commit=True)
        
        return jsonify({'message': '删除成功'})
    except Exception as e:
        return jsonify({'message': str(e)}), 500

# 搜索人员
@app.route('/api/personnel/search', methods=['GET'])
@token_required
def search_personnel():
    if not request.user.get('permissions', {}).get('can_edit_personnel'):
        return jsonify({'message': '没有权限访问此资源'}), 403

    keyword = request.args.get('keyword', '').strip()
    department = request.args.get('department', '').strip()

    try:
        # 构建搜索条件
        conditions = []
        params = []
        
        if keyword:
            conditions.append('(employee_id LIKE %s OR name LIKE %s)')
            params.extend([f'%{keyword}%', f'%{keyword}%'])
        
        if department:
            conditions.append('department = %s')
            params.append(department)

        # 组合SQL查询
        sql = 'SELECT * FROM personnel'
        if conditions:
            sql += ' WHERE ' + ' AND '.join(conditions)
        sql += ' ORDER BY create_time DESC'

        personnel = execute_db_query(sql, params)
        return jsonify(personnel)

    except Exception as e:
        return jsonify({'message': str(e)}), 500

# 添加一个管理员路由，用于清除所有session
@app.route('/admin/clear-sessions')
def clear_sessions():
    session.clear()
    return jsonify({'status': 'success', 'message': '所有会话已清除'})

# 设备管理API

# 获取所有设备
@app.route('/api/devices', methods=['GET'])
@token_required
def get_devices():
    # 检查权限
    if not request.user.get('permissions', {}).get('can_manage_device'):
        return jsonify({'message': '没有权限访问此资源'}), 403

    try:
        # 获取分页参数
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        offset = (page - 1) * per_page
        
        # 获取设备总数
        count = execute_db_query('SELECT COUNT(*) as count FROM devices', fetch_one=True)
        total = count['count'] if count else 0
        
        # 获取设备列表
        devices = execute_db_query(
            'SELECT * FROM devices ORDER BY create_time DESC LIMIT %s OFFSET %s', 
            (per_page, offset)
        )
        
        return jsonify({
            'data': devices,
            'pagination': {
                'total': total,
                'page': page,
                'per_page': per_page,
                'pages': (total + per_page - 1) // per_page
            }
        })
    except Exception as e:
        return jsonify({'message': str(e)}), 500

# 获取单个设备详情
@app.route('/api/devices/<int:device_id>', methods=['GET'])
@token_required
def get_device_by_id(device_id):
    if not request.user.get('permissions', {}).get('can_manage_device'):
        return jsonify({'message': '没有权限访问此资源'}), 403

    try:
        device = execute_db_query('SELECT * FROM devices WHERE device_id = %s', (device_id,), fetch_one=True)
        
        if device:
            # 如果设备存在，计算运行时间
            if device['operation_date'] and device['status'] == '正常运行':
                # 将operation_date转换为datetime对象
                operation_date = datetime.strptime(device['operation_date'].strftime('%Y-%m-%d'), '%Y-%m-%d')
                # 计算当前日期与投运日期之间的天数差
                days_running = (datetime.now() - operation_date).days
                # 将天数转换为小时
                hours_running = days_running * 24
                # 更新设备信息中的运行时间
                device['running_time'] = hours_running
            
            return jsonify(device)
        else:
            return jsonify({'message': '未找到该设备'}), 404
    except Exception as e:
        return jsonify({'message': str(e)}), 500

# 添加设备
@app.route('/api/devices', methods=['POST'])
@token_required
def add_device():
    if not request.user.get('permissions', {}).get('can_manage_device'):
        return jsonify({'message': '没有权限访问此资源'}), 403

    data = request.get_json()
    
    # 验证必填字段
    required_fields = ['device_name', 'device_number', 'device_type']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'message': f'缺少必填字段: {field}'}), 400

    try:
        # 检查设备编号是否已存在
        exists = execute_db_query('SELECT device_id FROM devices WHERE device_number = %s', 
                                 (data['device_number'],), fetch_one=True)
        if exists:
            return jsonify({'message': '设备编号已存在'}), 400

        # 如果提供了operation_date和设备状态为"正常运行"，自动计算running_time
        if data.get('operation_date') and data.get('status', '正常运行') == '正常运行':
            try:
                # 将operation_date转换为datetime对象
                operation_date = datetime.strptime(data['operation_date'], '%Y-%m-%d')
                # 计算当前日期与投运日期之间的天数差
                days_running = (datetime.now() - operation_date).days
                # 将天数转换为小时并更新数据
                data['running_time'] = days_running * 24
            except Exception as e:
                print(f"计算运行时间错误: {str(e)}")
                # 如果日期格式有误，设置为0
                data['running_time'] = 0
        else:
            # 如果没有投运日期或状态不是"正常运行"，运行时间为0
            data['running_time'] = 0
            
        # 构建SQL插入语句
        fields = []
        placeholders = []
        values = []
        
        # 添加所有非空字段到插入语句中
        for key, value in data.items():
            if value not in (None, ''):
                fields.append(key)
                placeholders.append('%s')
                values.append(value)
        
        sql = f'''
            INSERT INTO devices ({', '.join(fields)})
            VALUES ({', '.join(placeholders)})
        '''
        
        # 打印SQL和参数用于调试
        print(f"执行SQL: {sql}")
        print(f"参数值: {values}")
        
        # 执行插入操作
        execute_db_query(sql, values, commit=True)
        
        return jsonify({'message': '添加成功'}), 201
    except Exception as e:
        print(f"添加设备失败: {str(e)}")  # 详细错误信息
        return jsonify({'message': f'添加设备失败: {str(e)}'}), 500

# 更新设备信息
@app.route('/api/devices/<int:device_id>', methods=['PUT'])
@token_required
def update_device(device_id):
    if not request.user.get('permissions', {}).get('can_manage_device'):
        return jsonify({'message': '没有权限访问此资源'}), 403

    data = request.get_json()
    
    # 验证必填字段
    required_fields = ['device_name', 'device_type']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'message': f'缺少必填字段: {field}'}), 400

    try:
        # 检查设备是否存在
        exists = execute_db_query('SELECT device_id FROM devices WHERE device_id = %s', 
                                 (device_id,), fetch_one=True)
        if not exists:
            return jsonify({'message': '未找到该设备'}), 404

        # 如果更新了设备编号，检查新编号是否与其他设备冲突
        if data.get('device_number'):
            conflict = execute_db_query(
                'SELECT device_id FROM devices WHERE device_number = %s AND device_id != %s', 
                (data['device_number'], device_id), 
                fetch_one=True
            )
            if conflict:
                return jsonify({'message': '设备编号已被其他设备使用'}), 400

        # 如果提供了operation_date和设备状态为"正常运行"，自动计算running_time
        if data.get('operation_date') and data.get('status', '正常运行') == '正常运行':
            try:
                # 将operation_date转换为datetime对象
                operation_date = datetime.strptime(data['operation_date'], '%Y-%m-%d')
                # 计算当前日期与投运日期之间的天数差
                days_running = (datetime.now() - operation_date).days
                # 将天数转换为小时并更新数据
                data['running_time'] = days_running * 24
            except Exception as e:
                print(f"计算运行时间错误: {str(e)}")
                # 如果日期格式有误，设置为0
                data['running_time'] = 0
        elif data.get('status') and data.get('status') != '正常运行':
            # 如果设备状态不是"正常运行"，运行时间为0
            data['running_time'] = 0
            
        # 构建更新语句
        set_clauses = []
        values = []
        
        # 添加所有提供的字段到更新语句中
        for key, value in data.items():
            if key != 'device_id':  # 排除主键
                set_clauses.append(f'{key} = %s')
                values.append(value)
        
        # 添加device_id作为WHERE条件的参数
        values.append(device_id)
        
        sql = f'''
            UPDATE devices 
            SET {', '.join(set_clauses)}
            WHERE device_id = %s
        '''
        
        # 打印SQL和参数用于调试
        print(f"执行更新SQL: {sql}")
        print(f"更新参数值: {values}")
        
        # 执行更新操作
        execute_db_query(sql, values, commit=True)
        
        return jsonify({'message': '更新成功'})
    except Exception as e:
        print(f"更新设备失败: {str(e)}")  # 详细错误信息
        return jsonify({'message': f'更新设备失败: {str(e)}'}), 500

# 删除设备
@app.route('/api/devices/<int:device_id>', methods=['DELETE'])
@token_required
def delete_device(device_id):
    if not request.user.get('permissions', {}).get('can_manage_device'):
        return jsonify({'message': '没有权限访问此资源'}), 403

    try:
        # 检查设备是否存在
        exists = execute_db_query('SELECT device_id FROM devices WHERE device_id = %s', 
                                 (device_id,), fetch_one=True)
        if not exists:
            return jsonify({'message': '未找到该设备'}), 404

        # 删除设备记录
        execute_db_query('DELETE FROM devices WHERE device_id = %s', (device_id,), commit=True)
        
        return jsonify({'message': '删除成功'})
    except Exception as e:
        return jsonify({'message': str(e)}), 500

# 搜索设备
@app.route('/api/devices/search', methods=['GET'])
@token_required
def search_devices():
    if not request.user.get('permissions', {}).get('can_manage_device'):
        return jsonify({'message': '没有权限访问此资源'}), 403

    keyword = request.args.get('keyword', '').strip()
    device_type = request.args.get('device_type', '').strip()
    status = request.args.get('status', '').strip()

    try:
        # 构建搜索条件
        conditions = []
        params = []
        
        if keyword:
            conditions.append('(device_name LIKE %s OR device_number LIKE %s)')
            params.extend([f'%{keyword}%', f'%{keyword}%'])
        
        if device_type:
            conditions.append('device_type = %s')
            params.append(device_type)
            
        if status:
            conditions.append('status = %s')
            params.append(status)

        # 组合SQL查询
        sql = 'SELECT * FROM devices'
        if conditions:
            sql += ' WHERE ' + ' AND '.join(conditions)
        sql += ' ORDER BY create_time DESC'

        devices = execute_db_query(sql, params)
        return jsonify(devices)

    except Exception as e:
        return jsonify({'message': str(e)}), 500

# 文件相关接口

# 检查文件扩展名是否允许
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# 文件上传接口
@app.route('/api/upload', methods=['POST'])
@token_required
def upload_file():
    # 检查是否有文件被上传
    if 'file' not in request.files:
        return jsonify({'message': '没有文件部分'}), 400
    
    file = request.files['file']
    
    # 如果用户没有选择文件，浏览器也会提交一个空的文件部分而没有文件名
    if file.filename == '':
        return jsonify({'message': '没有选择文件'}), 400
    
    if file and allowed_file(file.filename):
        # 使用安全的文件名并加上唯一标识符以防止冲突
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4().hex}_{filename}"
        file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
        
        try:
            file.save(file_path)
            # 返回相对路径，便于前端访问
            relative_path = f"/static/uploads/{unique_filename}"
            return jsonify({
                'message': '文件上传成功',
                'file_path': relative_path
            }), 201
        except Exception as e:
            return jsonify({'message': f'保存文件时出错: {str(e)}'}), 500
    
    return jsonify({'message': '不允许的文件类型，只接受 png, jpg, jpeg, gif 格式的图片'}), 400

# 安全地处理文件名
def secure_filename(filename):
    return werkzeug.utils.secure_filename(filename)

if __name__ == '__main__':
    app.run(debug=True, port=5000)