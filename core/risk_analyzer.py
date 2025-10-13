from enum import Enum

class RiskLevel(Enum):
    """风险等级枚举（数值越大风险越高）"""
    # 严重漏洞
    CRITICAL1 = 100  # 敏感密钥文件泄露
    CRITICAL2 = 95   # 数据库备份泄露
    CRITICAL3 = 90   # 匿名上传漏洞（PUT/POST）
    CRITICAL4 = 85   # 匿名删除漏洞（DELETE）  # 新增
    
    # 高危漏洞
    HIGH1 = 80       # 公开可列目录
    HIGH2 = 75       # 访问日志泄露  # 新增
    
    # 中危漏洞
    MEDIUM1 = 60     # 配置文件泄露
    MEDIUM2 = 55     # CORS配置过度宽松
    MEDIUM3 = 50     # 目录遍历漏洞  # 新增
    
    # 低危漏洞
    LOW1 = 30        # 低风险文件泄露
    LOW2 = 20        # Bucket存在但不可访问
    LOW3 = 10        # 敏感HTTP头泄露  # 新增
    
    # 错误/信息
    ERROR = 0        # 扫描错误
    INFO = -1        # 普通信息

    def __str__(self):
        return self.name

    @classmethod
    def get_level_name(cls, level_value):
        """根据数值返回风险等级名称（新增等级需同步）"""
        for level in cls:
            if level.value == level_value:
                return level.name
        return "UNKNOWN"