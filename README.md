# Kernel-Trace
一个基于uprobe，能同时hook大量用户地址空间函数的kpm内核模块


# 如何使用
在成功加载本项目的kpm模块后，可通过 **dmesg | grep +Test-Log+** 命令查看模块日志，再使用项目user目录下的uprobe_trace_user.h文件提供的用户层接口进行编程即可。trace的输出结果在tracefs文件系统下，可通过 **mount | grep tracefs** 命令查看tracefs所在位置，一般都是在/sys/kernel/tracing，通过 **echo "1" >> /sys/kernel/tracing/tracing_on** 开启日志后通过 **cat /sys/kernel/tracing/trace_pipe | grep +Test-Log+** 查看trace的结果。

**trace_init**函数用于设置要hook so的基本信息(包括目标so模块基址，hook的app的uid，目标so模块的完整路径，替代so模块的完整路径)。

**set_fun_info**函数用于设置要hook函数的信息(包括函数的uprobe偏移，计算方法见文末,以及目标函数的偏移和自定义的函数名)。

**clear_all_uprobes**函数用于清除所有的uprobe挂载点。

上述函数的返回结果有SET_TRACE_SUCCESS、SET_TRACE_ERROR两种，分别表示设置成功和失败。

# 使用示例
编程思路可以参考[示例](https://github.com/AndroidReverser-Test/KernelTraceDemo/blob/main/app/src/main/cpp/kerneltracedemo.cpp)

# 支持的内核版本
目前只在5.10以及5.15两个版本通过测试，理论上5.10以上版本都能正常使用。2026/01/17更新,理论上支持6系内核(在部分机型上可能会有bug)。

# 函数的uprobe偏移
简单来说就是函数地址减去所在内存段的基地址再加上该内存段内存区域的偏移量所得的值。
计算示例如下：
以下图片展示了一个so文件在maps文件中的区域段
![计算示例](./pic/偏移计算.JPG)
假如一个函数的地址为0x7626323000,那要hook这个函数那传给uprobe_register函数的偏移值应该为0x7626323000-0x7626322000+0x90000=0x91000.

## uprobe无法对加固过的so进行hook？
在对应so的代码段没有被加密的情况下，uprobe是能正确获取到将要被**brk #5**覆盖的原始汇编指令，但当so的代码段是在运行时才解密时，
uprobe获取到的汇编指令往往都是没有解密前的密文汇编指令，这些密文汇编指令当然是无法被执行的，这就会引发app的直接崩溃。

## 解决方案
让用户提供替代so模块。
简单地说就是不再让uprobe在缓存中获取所需的汇编指令， 而是直接让uprobe读取本地文件来获取所需要的正确的汇编指令。
一般的so模块就算是静态加密的， 运行时也会解密，用户只需将包含正确汇编指令的so模块dump下放到自己设置的指定路径即可。
这样就能直接解决uprobe不能实时获取内存中的汇编指令的问题。

## 一些bug
对一些app使用模块后在退出时如果没有先使用UprobeClearer清除设置的uprobe挂载点而重新打开app有可能会出现设备卡住的情况。
有可能部分设备没有兼容，加载模块会失败，或者是调用api后卡住。