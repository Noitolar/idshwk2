# SNORT 第二次笔记

## 复习：几种规则动作

| 动作   | 描述                                                         |
| ------ | :----------------------------------------------------------- |
| alert  | 基于规则对应的告警消息生成一个警告，并将数据包记录日志       |
| log    | 将数据包记录日志                                             |
| pass   | 忽略这个数据包                                               |
| Drop   | 使用 iptables 丢弃这个数据包，并将数据包记录入日志           |
| Sdrop  | 使用 iptables 丢弃这个数据包，但不记录日志                   |
| Reject | 使用 iptables 丢弃数据包，记录日志，并发送一个 TCP-reset或者ICMP-unreachable |

## 复习：几个规则选项 content 的修饰属性

| 选项      | 描述                                                         |
| --------- | ------------------------------------------------------------ |
| offset    | content的搜索起点，默认为0                                   |
| depth     | 从offset开始的搜索深度                                       |
| distance  | (多个content时使用)下一个content相对于上一个搜索区域的距离，相当于"跳过" |
| within    | (多个content时使用)distance的depth                           |
| nocase    | 大小写不敏感                                                 |
| raw_bytes | 不进行解码，直接进行字节匹配                                 |

### 例子

alert tcp any any -> any 3306 (

msg:"ATTACK!!!";  //在报警和包日志中打印的消息内容

flow:to_server,established; //检测向服务器发送方向的报文

 dsize:<300;  //应用层负载包长度小于300

flags:A;  //TCP flags值为ACK

content:"YPA!"; nocase; offset:4; depth:10; //负载偏移4~14的区域有一个"乌拉!"且不区分大小写

content:"|20|"; distance:10; within:50; //相对于上面的ypa!特征向后偏移10个字节之后再取50个字节，也就是15~65字节，50个字节里边包含十六进制的20

reference:cve,2013-1861;  //参考规则(cve,2013-1861是一个url)

classtype-danger:medium;  //危险等级：中等

sid:14999; rev:1;) //规则编号14999，第1版

## 正则表达式选项：pcre

常用表达式：

* 数字："/[0-9]*/"
* n位的数字："/\d{n}/"
* 至少n位的数字："/\d{n,}/"
* m-n位的数字："/\d{m,n}/"
* 零和非零开头的数字："/(0|\[1-9\]\[0-9\]*)/"
* 汉字："/[\u4e00-\u9fa5]{0,}/"
* 英文和数字："/[A-Za-z0-9]+/" 或 "/[A-Za-z0-9]{4,40}/"
* 长度为3-20的所有字符："/.{3,20}/"
* 由26个英文字母组成的字符串："/[A-Za-z]+/"
* 由26个大写英文字母组成的字符串："/[A-Z]+/"
* 由数字和26个英文字母组成的字符串："/[A-Za-z0-9]+/"
* 由数字、26个英文字母或者下划线组成的字符串："/\w+/" 或 "/\w{3,20}/"

## 规则选项：flowbits

用于会话跟踪的场景，对于TCP会话特别有用，允许跟踪应用层的协议。规则编写者可以为自己设定的某个会话状态设定一个名称，一些关键字使用group name。当没有group name的时候，snort引擎将认为它是默认的group。

| flowbits选项       | flowbits功能描述                                             |
| ------------------ | ------------------------------------------------------------ |
| flowbits: set      | 为当前的flow状态设置一个flowbits名称，同时为它分配一个group  |
| flowbits: setx     | 为当前的flow状态设置一个flowbits名称，同时清除group内其他的状态名称 |
| flowbits: unset    | 清除掉flowbits名称                                           |
| flowbits: toggle   | 对当前flowbits取反                                           |
| flowbits: isset    | 判断是否已经设置flowbits                                     |
| flowbits: isnotset | 判断是否还未设置flowbits                                     |
| flowbits: noalert  | 让snort对这个flow不产生警报，即便匹配成功                    |
| flowbits: reset    | 重设flow的全部状态                                           |

### 例子

alert tcp any 143 -> any any (msg:"IMAP login"; content:"OK LOGIN"; flowbits: set, logged_in; flowbits: noalert)

## 本次作业内容

snort在一个flow中收到两个TCP报文：

* 第一个报文在负载中包含了"login"或"Initial"，宿端口是3399
* 第二个报文在负载中包含了"IpV4地址:端口号"格式的字符串，宿端口也是3399
* 当这两个条件同时满足时，触发警报"bot founded"，规则编号1000001

## 作业作答

### 规则一

#### 规则头

log tcp $EXTERNAL_NET any -> $HOME_NET 3399

#### 规则选项

| 属性     | 内容                      | 解释                                         |
| -------- | ------------------------- | -------------------------------------------- |
| pcre     | "/login\|Initial/"        | -                                            |
| flowbits | set, QAQ_Attack_Is_Coming | 把flowbits状态开启，组名QAQ_Attack_Is_Coming |
| sid      | 114514                    | -                                            |

### 规则二

#### 规则头

alert tcp $EXTERNAL_NET any -> $HOME_NET 3399

#### 规则选项

| 属性      | 内容                        | 解释                            |
| --------- | --------------------------- | ------------------------------- |
| msg       | "bot founded"               | -                               |
| pcre      | "/具体写在下面/"            | 0.0.0.0:0~255.255.255.255:65535 |
| flowbites | isset, QAQ_Attack_Is_Coming | 如果已经有QAQ的flag则确认触发   |
| sid       | 1000001                     | -                               |

补：pcre内容：

* 0~255的数字：2\[0-5\]\[0-5\] 或 1\d{2} 或 \[1-9\]\d 或 \d
  * 后两个可以合并成"[1-9]?\d"
* 0~65535的数字：6[0-5\]{2}\[0-3\]\[0-5\] 或 \[1-5\]\d{4} 或 \[1-9\]\d{1,3} 或 \d

即pcre选项内容为："/(2\[0-5\]\[0-5\]|1\d{2}|\[1-9\]\d|\d\\.){3}(2\[0-5\]\[0-5\]|1\d{2}|\[1-9\]\d|\d):(6[0-5\]{2}\[0-3\]\[0-5\]|\[1-5\]\d{4}|\[1-9\]\d{1,3}|\d)/"

规则一和规则二分别写为：

* log tcp $EXTERNAL_NET any -> $HOME_NET 3399 (pcre: "/login\|Initial/"; flowbits: set, QAQ_Attack_Is_Coming; sid: 114514)
* log tcp $EXTERNAL_NET any -> $HOME_NET 3399 (msg: "bot founded"; pcre: "/(2\[0-5\]\[0-5\]|1\d{2}|\[1-9\]\d|\d\\.){3}(2\[0-5\]\[0-5\]|1\d{2}|\[1-9\]\d|\d):(6[0-5\]{2}\[0-3\]\[0-5\]|\[1-5\]\d{4}|\[1-9\]\d{1,3}|\d)/"; flowbits: isset, QAQ_Attack_Is_Coming; sid: 1000001)