# UprobeClearer
一个可执行文件，用于一键清除所有的uprobes挂载点，防止app因残留的uprobe点崩溃。


# 构建
将ndk所在路径设置为环境变量后，在当前项目路径下执行ndk-build即可自动生成相应可执行文件。