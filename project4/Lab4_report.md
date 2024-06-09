# Lab4 - FUSE passthrough

简单了解FUSE并阅读框架代码后，可以理解passthrough的大致思路：
自定义一系列用户文件系统函数`xmp_xxxx()`，指定挂载点，最后交由`fuse_main(new_argc, new_argv, &xmp_oper, NULL);`进行挂载。默认挂载整个根文件系统。

`--hidden_file_name=xxxx`等自定义命令行参数由`fuse_opt_parse(&args, &options, option_spec, NULL)`进行解析并保存在`options`结构中，之后并不会传递给`fuse_main()`。

因此实现思路为在自定义的用户文件系统函数中对`options`参数指定的文件进行操作

### 文件路径解析
考虑到输入参数可能是绝对路径，也可能是相对路径，并且需要进行特殊操作的是某一指定文件路径而非inode本身，所以在参数解析后利用`realpath()`系统调用将路径转为绝对路径备用。
```c
	/* Expand relative path to absolute path */
	char buf[1024];
	if (strcmp(options.hidden_file_name, "")) {
		realpath(options.hidden_file_name, buf);
		options.hidden_file_name = strdup(buf);
	}
```

### 隐藏文件
在FUSE中隐藏指定文件路径，只需要让`l`等命令不列出该文件即可。而FUSE中的`ls`会调用`xmp_readdir`来遍历目录下的所有文件，因此只要让`xmp_readdir`跳过该文件
```c
static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi,
		       enum fuse_readdir_flags flags)
{
	DIR *dp;
	struct dirent *de;
	char filename[1024];

	(void) offset;
	(void) fi;
	(void) flags;

	dp = opendir(path);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		/* Resolve absolute path */
		sprintf(filename, "%s/%s", path, de->d_name);
		if (!strcmp(realpath(filename, NULL), options.hidden_file_name))
			continue;

		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0, fill_dir_plus))
			break;
	}

	closedir(dp);
	return 0;
}
```

### 加密文件
FUSE读取文件时会调用`xmp_read()`，因此同理修改其读到的数据即可
```c
static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	int fd;
	int res;

	if(fi == NULL)
		fd = open(path, O_RDONLY);
	else
		fd = fi->fh;
	
	if (fd == -1)
		return -errno;

	res = pread(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	if (!strcmp(realpath(path, NULL), options.encrypted_file_name)) {
		// Encrypt the file
		for (int i = 0; i < res; i++) {
			buf[i] = (buf[i] + 1) % 255;
		}
	}

	if(fi == NULL)
		close(fd);
	return res;
}
```

### 执行文件
同理，在`xmp_getattr`中修改FUSE下该文件的权限即可
```c
static int xmp_getattr(const char *path, struct stat *stbuf,
		       struct fuse_file_info *fi)
{
	(void) fi;
	int res;

	res = lstat(path, stbuf);
	if (res == -1)
		return -errno;

	/* Add exec permissions */
	if (!strcmp(realpath(path, NULL), options.exec_file_name)) {
		stbuf->st_mode |= S_IXUSR | S_IXGRP | S_IXOTH;
	}

	return 0;
}
```