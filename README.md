# glassfish_PoC

本源码由python语言编写

author：Ninggo

提供对glassfish的任意文件读取漏洞探测。

## 漏洞原理

glassfish是一款java编写的跨平台的开源的应用服务器。

java语言中会把%c0%ae解析为\uC0AE，最后转义为ASCCII字符的.（点）
利用%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/来向上跳转，达到目录穿越、任意文件读取的效果。



## 影响版本

glassfish4.0/4.1

## 安装要求

1.python3版本以上

2.采用Pocsuite3框架

## 

## 测试

命令行运行python脚本，输入域名

使用方式：python3 glassfish_PoC.py

​	参数：-u 指定url

​				-f 指定扫描文件内容

​				-o 扫描结果输出文件

其余可选参数适用于pocsuite3，按情况使用。

本源码只编写了Linux环境下的任意文件读取，如果由windows环境搭建，可以自行修改源码payload。

如果有大佬可以对代码进行优化感激不尽。