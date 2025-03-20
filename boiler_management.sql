-- 创建数据库
CREATE DATABASE IF NOT EXISTS boiler_system DEFAULT CHARSET utf8mb4;
USE boiler_system;

-- 角色权限表（多级权限控制）
CREATE TABLE roles (
    role_id INT PRIMARY KEY AUTO_INCREMENT,
    role_name VARCHAR(20) NOT NULL UNIQUE,  -- 角色名称
    can_edit_personnel BOOLEAN DEFAULT 0,   -- 是否可修改人员信息
    can_manage_device BOOLEAN DEFAULT 0,    -- 设备管理权限
    can_view_reports BOOLEAN DEFAULT 1,     -- 报表查看权限
    description VARCHAR(255)               -- 角色描述
);

-- 员工信息表
CREATE TABLE personnel (
    employee_id VARCHAR(10) PRIMARY KEY,  -- 工号（字母+数字组合）
    name VARCHAR(20) NOT NULL,           -- 姓名
    department VARCHAR(30) NOT NULL,     -- 所属部门
    position VARCHAR(30) NOT NULL,       -- 职位
    contact_phone VARCHAR(15),           -- 联系电话
    email VARCHAR(50),                   -- 电子邮箱
    create_time BIGINT,                  -- 添加时间（Unix时间戳秒数）
    update_time BIGINT                   -- 最后更新时间（Unix时间戳秒数）
);

-- 系统用户表（与员工信息关联）
CREATE TABLE users (
    user_id INT PRIMARY KEY AUTO_INCREMENT,
    employee_id VARCHAR(10) UNIQUE NOT NULL,
    username VARCHAR(20) UNIQUE NOT NULL,  -- 登录账号
    password_hash VARCHAR(64) NOT NULL,    -- SHA256加密存储
    role_id INT NOT NULL,
    is_active BOOLEAN DEFAULT 1,          -- 账户状态
    FOREIGN KEY (employee_id) REFERENCES personnel(employee_id),
    FOREIGN KEY (role_id) REFERENCES roles(role_id)
);

-- 设备表
CREATE TABLE devices (
    device_id INT PRIMARY KEY AUTO_INCREMENT,
    device_name VARCHAR(50) NOT NULL,              -- 设备名称
    device_number VARCHAR(50) NOT NULL UNIQUE,     -- 设备编号（唯一）
    device_type ENUM('锅炉', '燃烧器', '空气预热器', '给水泵', '引风机', 
                     '送风机', '一次风机与煤粉机', '磨煤机', '给煤机', 
                     '给粉机', '吹灰器') NOT NULL,   -- 设备类型
    responsible_person VARCHAR(30),               -- 设备负责人
    create_time BIGINT,                           -- 添加时间（Unix时间戳秒数）
    update_time BIGINT,                           -- 最后更新时间（Unix时间戳秒数）
    brand VARCHAR(50),                           -- 设备品牌
    model VARCHAR(50),                           -- 设备型号
    image_path VARCHAR(200),                     -- 设备图片路径
    
    -- 运行状态
    status ENUM('正常运行', '故障', '维修中', '待机') DEFAULT '正常运行', -- 设备状态
    location VARCHAR(100),                       -- 安装位置
    running_time INT DEFAULT 0,                  -- 运行时间（小时）
    
    -- 维护与管理
    purchase_date DATE,                          -- 采购日期
    operation_date DATE,                         -- 投运日期
    warranty_period VARCHAR(30),                 -- 保修期
    supplier_info TEXT,                          -- 供应商信息
    maintenance_person VARCHAR(30),              -- 维护负责人
    maintenance_cycle VARCHAR(30),               -- 维护周期
    
    -- 附加信息
    notes TEXT                                   -- 备注
);

-- 初始化角色数据
INSERT INTO roles (role_name, can_edit_personnel, can_manage_device, description) VALUES
('系统管理员', 1, 1, '拥有所有权限，可管理用户和设备'),
('技术主管', 1, 0, '可管理人员信息，查看所有数据'),
('操作员', 0, 0, '仅查看基础信息，无编辑权限'),
('维护工程师', 0, 1, '可管理设备信息，不可修改人员');

-- 示例用户数据（密码032236）
-- 使用当前Unix时间戳
SET @current_timestamp = UNIX_TIMESTAMP();

INSERT INTO personnel (employee_id, name, department, position, create_time, update_time) VALUES
('ADM001', '张伟', '信息部', '系统管理员', @current_timestamp, @current_timestamp),
('TEC101', '李芳', '技术部', '技术主管', @current_timestamp, @current_timestamp),
('OPE201', '王刚', '运行部', '操作员', @current_timestamp, @current_timestamp);

INSERT INTO users (employee_id, username, password_hash, role_id) VALUES
('ADM001', 'admin', SHA2('032236', 256), 1),
('TEC101', 'lifang', SHA2('032236', 256), 2),
('OPE201', 'wanggang', SHA2('032236', 256), 3); 