# 锅炉信息管理系统 (BIMS)

这是一个基于Flask的锅炉信息管理系统Web应用，用于管理锅炉设备信息、人员和权限。

## 功能特点

- 多级用户权限管理（系统管理员、技术主管、操作员、维护工程师）
- 人员信息管理和权限控制
- 设备信息管理（锅炉、燃烧器、空气预热器等）
- 设备状态监控和记录
- 维护信息跟踪
- 文件上传功能

## 技术栈

- 后端: Flask (Python)
- 前端: HTML, CSS, JavaScript
- 数据库: MySQL
- 认证: JWT (JSON Web Token)

## 安装和配置

1. 克隆仓库
```
git clone https://github.com/Mirrorccc/BIMS-0.11.git
cd BIMS-0.11
```

2. 安装依赖
```
pip install -r requirements.txt
```

3. 配置数据库
- 确保已安装MySQL数据库
- 更新app.py中的数据库配置
```python
db_config = {
    'host': 'localhost',
    'user': 'your_username',
    'password': 'your_password',
    'database': 'boiler_system'
}
```
- 导入数据库脚本
```
mysql -u your_username -p < boiler_management.sql
```

4. 运行应用
```
python app.py
```

5. 访问应用
浏览器打开 http://localhost:5000

## 默认账户

- 管理员账户: admin / 032236
- 技术主管: lifang / 032236
- 操作员: wanggang / 032236

## 目录结构

- `app.py`: 主应用程序文件
- `boiler_management.sql`: 数据库创建脚本
- `static/`: 静态资源文件夹
  - `styles.css`: 样式表
  - `images/`: 图片资源
  - `uploads/`: 上传文件存储目录
- `templates/`: HTML模板文件夹
  - `login.html`: 登录页面
  - `dashboard.html`: 管理仪表板 