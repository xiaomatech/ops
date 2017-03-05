#原则
    1,纯原生 无agent(libvirt,docker,ovs等本身就是超级agent)
    2,restful 易组合
    3,提供类似 aws-shell,kubectl的命令行工具
    4,极简

#架构图,流程图
    todo

#安装
    安装mysql
        yum install -y mysql-server

    导入表
        mysql -uroot -p123456 <schemas/*.sql

    修改configs/__init__.py的配置

    启动
        ./start.sh

