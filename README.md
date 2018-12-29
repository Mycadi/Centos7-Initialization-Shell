# Centos7-Initialization-Shell

# Centos7 VM初始化脚本

说明：安装完成centos7系统后对系统进行初始化安全设置，脚本遵循集团基线安全要求编写，由于集团服务器与个人机器有点区别，已经把内网一些不需要的初始化规则去除，使用者请自行修改使用。


使用说明：
ZIP文件需要传到非root用户家目录中。
运行脚本必须要root用户，脚本参数是用于切换root用的，其他用户均不能切换root。
运行规则 sh centos7_system_init.sh user
