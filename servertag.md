核心原理

    按照小米的tag模型 http://noops.me/?p=289
    
    
    系统的设计概要如下：
    
    通过层级和tag的方式为每一台物理/虚拟的服务器做标记，外围系统通过组合查询的方式拿到所需要的机器列表。
    
    每个tag代表一种属性，属性可以是各种各样的。比如可以标记服务器故障下线，可以标记服务器运行了一个程序nginx，标记服务器的属主是某个team，可以标记服务器的idc位置，可以标记服务器是个虚拟机，等等。总之我们的目的是希望将服务器所有可能需要用到的属性都做一个标记，以便我们在需要的时候方便、快捷的取出来。
    
    系统包括（但不仅限于）以下功能：
    
    提供完善的增删改API接口，提供一套查询语法规则。
    
    可以生成以服务器为单位，用来准确、直观的反映服务层级关系的动态树状模型。
    
    支持不同维度去初始化动态树。
    
    通过对tag授权，实现人员/组到机器粒度的授权。
    
    以下分要点进行详解。
    
    一、level、tag、schema
    
    Level和tag都是两个抽象的概念，本质作用都是用来对某些属性进行描述，并将其应用到服务器上。从原则上来说不同的level是平级的，并没有附属关系。Schema指为了初始化动态树作为展示（web），所需要定义的不同level之间的层级关系。
    
    Level可以理解为对于一类属性的合集。
    
    举几个自己定义的例子：
    
    Level	Level中文含义	Level说明	tag举例	是否必须	是否关联
    cop	Company，公司	表示公司属性。一般可以有一个默认的属性（公司业务没有子公司）	xiaomi,duokan	是	是
    owt	Owner team，所有组	表示所有组（运维组）的属性	miliao,miui	是	是
    loc	Location，地域		bj、gz、us	是	是
    idc	IDC，数据中心		sd、dg、sjhl	是	是
    pdl	Product line，产品线		ml、b2c、dba	是	是
    sbs	Subsystem，子系统		fe、ln、im、mfs、hadoop		
    srv	Service，服务				
    mod	Module，模块		ejd、xmq	是	是
    grp	Group，分组		00、01、02		
    ptn	Partition，分区		20m-50m、50m-70m		
    cln	Cluster-node，集群节点		master、slave		
    fls	Flow-status，流量情况		full、exp		
    status	机器状态	机器可以有几种状态 
    在线、故障下线、待交付等
    
    online、offline、delivered	是	否
    virt	是否虚拟机		n,y		
     
    
    说明：
    
    1、表中定义的“是否必须”列，其中如果为“是”。则表示机器在加入服务树的时候必须要有此level层级的tag，否则不予添加。
    
    2、level可以根据需要任意添加，每个level下的tag可以枚举；在添加的tag的时候要考虑清楚适用的场景是什么，是一个独立的属性还是用来表示关联关系。
    
    3、level要保持唯一性。同一个level下面的tag不能重复，不同level下可以有相同的tag名称。在每一台机器上可以在同一个level下有多个tag。
    
    4、关联tag是指tag在关联到机器上的时候，以tag组的形式保存。关联tag的引入是为了解决多个tag组合查询的时候，多对多造成的多种组合（实际上我们要的只是一种组合）。
    
    举个例子，某个机器有这么一个关联tag：cop.c_owt.t_idc.i_loc.l _pdl.p _sbs.s_mod.m。
    
    独立tag有如下几个status.online、virt.n。
    
    参照上面的表格，这里解释一下以上的各种tag所表示的含义。cop.c表示这台机器有一个“属于c这个公司”的属性，owt.t表示此机器有个“属于t这个team”的属性。loc、pdl、sbs、mod的几个也是同样的道理。status.online表示此机器是在线服务状态，virt.n表示此机器不是虚拟机（那就是物理机器）。