use std::{
    ffi::OsString,
    fs::File,
    io::{BufRead, BufReader},
    os::unix::prelude::{OsStrExt, OsStringExt},
    time::Duration,
};

use crate::{
    fs::{Directory, FileKind, Inode},
    tde_cursor::TDECursor,
    utils::{
        time_util::{self, now},
        traits::SerializeAndDigest,
    },
    Group,
};

use super::MyFS;

use fuser::{FileAttr, Filesystem, TimeOrNow};

use log::info;
use memmap2::MmapMut;
impl Filesystem for MyFS {
    // to init the filesystem
    fn init(
        &mut self,
        _req: &fuser::Request<'_>,
        _config: &mut fuser::KernelConfig,
    ) -> Result<(), libc::c_int> {
        // config.add_capabilities(FUSE_HANDLE_KILLPRIV).unwrap();
        let superblock = self.superblock_mut();
        superblock.update_last_mounted_at();
        Ok(())
    }

    // to umount the filesystem
    fn destroy(&mut self) {
        let mut image_file_mmap =
            std::mem::replace(self.image_file_mmap_mut(), MmapMut::map_anon(0).unwrap());
        let block_size = 
            self.superblock().block_size
        ;
        let mut cursor = TDECursor::new(&mut image_file_mmap, block_size as u64);
        self.superblock_mut().serialize_into(&mut cursor).unwrap();

        Group::serialize_into(&mut cursor, self.superblock().block_size, self.groups()).unwrap();

        image_file_mmap.flush().unwrap();
    }

    // to show FS information
    fn statfs(&mut self, _req: &fuser::Request<'_>, _ino: u64, reply: fuser::ReplyStatfs) {
        let superblock = self.superblock();
        // now `file node count` is equal to `inode count`
        reply.statfs(
            superblock.block_count,
            superblock.free_blocks_count,
            superblock.free_blocks_count,
            superblock.inode_count - superblock.free_inodes,
            superblock.free_inodes,
            superblock.block_size,
            255, // this is equal to `max filename length` in Linux
            superblock.block_size,
        )
    }

    fn getattr(&mut self, _req: &fuser::Request<'_>, ino: u64, reply: fuser::ReplyAttr) {
        info!("getattr() called with inode number: {:?}", ino);
        let ttl = Duration::new(0, 0);
        let Ok(inode) = self.find_inode(ino)else{
            reply.error(libc::ENOENT);
            return;
        };
        reply.attr(&ttl, &inode.into());
    }

    fn getxattr(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        name: &std::ffi::OsStr,
        size: u32,
        reply: fuser::ReplyXattr,
    ) {
        info!(
            "getxattr() called with inode number: {:?}, name: {:?}, size: {:?}",
            ino, name, size
        );
        // do nothing
        reply.size(size)
    }
    // to read from a file
    fn read(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        flags: i32,
        lock_owner: Option<u64>,
        reply: fuser::ReplyData,
    ) {
        info!(
            "read() called with inode number: {:?}, fh: {:?}, offset: {:?}, size: {:?}, flags: {:?}, lock_owner: {:?}",
            ino, fh, offset, size, flags, lock_owner
        );
        let Ok(mut inode) = self.find_inode(ino) else{
            reply.error(libc::EINVAL);
            return;
        };
        let mut offset: u64 = offset as u64;
        let block_size = self.superblock().block_size;
        // Could underflow if file length is less than local_start
        let should_read =
            std::cmp::min(size, inode.file_size.saturating_sub(offset) as u32) as usize;
        let mut total_read: usize = 0;
        let mut buf = vec![0u8; should_read];
        while total_read != should_read {
            let block_to_read_index = offset / block_size as u64;
            let Ok((block_index, space_left))= self.find_data_block(&mut inode, offset, true) else{
                reply.error(libc::EIO);
                return;
            };

            let max_read_len = buf.len().min(space_left as usize);
            let max_read_len = buf.len().min(max_read_len + total_read);

            let offset_in_block = if total_read != 0 {
                // it is not the first block to read
                0
            } else {
                // it is the first block to read
                offset - block_to_read_index * block_size as u64
            };

            let Ok(read) = self
                .read_data_from_data_block(
                    &mut buf[total_read..max_read_len],
                    offset_in_block,
                    block_index,
                )
              else{
                reply.error(libc::EIO);
                return;
                };
            dbg!(read);
            total_read += read;
            offset += read as u64;
        }

        inode.update_accessed_at();
        let Ok(_) = self.save_inode(&mut inode, ino) else{
            reply.error(libc::EIO);
            return;
        };

        reply.data(&buf);
    }
    // to write to a file
    fn write(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        write_flags: u32,
        flags: i32,
        lock_owner: Option<u64>,
        reply: fuser::ReplyWrite,
    ) {
        info!(
                "write() called with inode number: {:?}, fh: {:?}, offset: {:?}, data: {:?}, write_flags: {:?}, flags: {:?}, lock_owner: {:?}",
                ino, fh, offset, data, write_flags, flags, lock_owner
            );

        // if offset < 0, return EINVAL
        if offset < 0 {
            reply.error(libc::EINVAL);
            return;
        }

        // find corresponding inode of the file to write
        let Ok(mut inode) = self.find_inode(ino) else{
                reply.error(libc::ENOENT);
                return;
        };

        let mut offset = offset as u64;
        // let overwrite = inode.file_size > offset;
        if offset + data.len() as u64 > inode.file_size {
            // if the file is not large enough to hold the data, then extend the file
            inode.file_size = offset + data.len() as u64;
        }
        let block_size = self.superblock().block_size;
        let _end_offset = offset as usize + data.len();

        let mut total_wrote = 0;
        let data_to_write = data.len();
        while total_wrote < data_to_write {
            let direct_block_index = offset / block_size as u64;
            let Ok((block_index, block_size)) = self.find_data_block(&mut inode, offset, false) else{
                    reply.error(libc::ENOENT);
                    return;
            };

            let max_write_len = data.len().min(block_size as usize);
            let offset_in_block = if total_wrote != 0 {
                // this is not the first block to write,so the offset is 0
                0
            } else {
                // this is the first block to write, so the offset is the offset in the block
                offset - direct_block_index * block_size as u64
            };
            let Ok(wrote) = self
                .write_data_to_data_block(
                    &data[total_wrote..data.len().min(max_write_len + total_wrote)],
                    offset_in_block,
                    block_index,
                )else {
                    reply.error(libc::EIO);
                    return;
                };

            total_wrote += wrote;
            offset += wrote as u64;
        }

        inode.update_modified_at();
        let Ok(_) = self.save_inode(&mut inode, ino).map_err(|_| libc::EIO)else{
            reply.error(libc::EIO);
            return;
        };
        reply.written(data.len() as u32);
    }
    // to set file attributes
    fn setattr(
        &mut self,
        req: &fuser::Request<'_>,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<fuser::TimeOrNow>,
        mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<std::time::SystemTime>,
        fh: Option<u64>,
        _crtime: Option<std::time::SystemTime>,
        _chgtime: Option<std::time::SystemTime>,
        _bkuptime: Option<std::time::SystemTime>,
        _flags: Option<u32>,
        reply: fuser::ReplyAttr,
    ) {
        info!(
            "setattr() called with inode number: {:?}, mode: {:?}, uid: {:?}, gid: {:?}, size: {:?}, atime: {:?}, mtime: {:?}, fh: {:?}",
            ino, mode, uid, gid, size, atime, mtime, fh
        );
        // find the inode to change metadata
        let Ok(mut inode) = self.find_inode(ino) else {
                    reply.error(libc::EINVAL);
                    return;
            };
        let attrs: FileAttr = inode.clone().into();
        let now = time_util::now();
        // if the user wants to "chmod"
        // if let Some(mode) = mode {
        //     info!("chmod() called with {:?}, {:o}", inode, mode);
        //     if req.uid() != 0 && req.uid() != inode.user_id {
        //         reply.error(libc::EPERM);
        //         return;
        //     }
        //     if req.uid() != 0
        //         && req.gid() != attrs.gid
        //         && !get_groups(req.pid()).contains(&inode.group_id)
        //     {
        //         // If SGID is set and the file belongs to a group that the caller is not part of
        //         // then the SGID bit is suppose to be cleared during chmod
        //         inode.mode = mode & !libc::S_ISGID;
        //     } else {
        //         inode.mode = mode;
        //     }
        //     inode.modified_at = Some(time::now().sec);
        //     self.save_inode(inode, ino as u32, None);
        //     reply.attr(&Duration::new(0, 0), &attrs);
        // }
        // // the user wants to "chown"
        // if uid.is_some() || gid.is_some() {
        //     info!("chown() called with {:?} {:?} {:?}", inode, uid, gid);
        //     if let Some(gid) = gid {
        //         // Non-root users can only change gid to a group they're in
        //         if req.uid() != 0 && !get_groups(req.pid()).contains(&gid) {
        //             reply.error(libc::EPERM);
        //             return;
        //         }
        //     }
        //     if let Some(uid) = uid {
        //         if req.uid() != 0
        //             // but no-op changes by the owner are not an error
        //             && !(uid == attrs.uid && req.uid() == attrs.uid)
        //         {
        //             reply.error(libc::EPERM);
        //             return;
        //         }
        //     }
        //     // Only owner may change the group
        //     if gid.is_some() && req.uid() != 0 && req.uid() != attrs.uid {
        //         reply.error(libc::EPERM);
        //         return;
        //     }

        //     // if inode.mode & (libc::S_IXUSR | libc::S_IXGRP | libc::S_IXOTH) != 0 {
        //     //     // SUID & SGID are suppose to be cleared when chown'ing an executable file
        //     //     clear_suid_sgid(&mut attrs);
        //     // }

        //     if let Some(uid) = uid {
        //         inode.user_id = uid;
        //         // Clear SETUID on owner change
        //         inode.mode &= !libc::S_ISUID;
        //     }
        //     if let Some(gid) = gid {
        //         inode.group_id = gid;
        //         // Clear SETGID unless user is root
        //         if req.uid() != 0 {
        //             inode.mode &= !libc::S_ISGID;
        //         }
        //     }
        //     inode.changed_at = Some(now);
        //     self.save_inode(inode, ino as u32, None);
        //     reply.attr(&Duration::new(0, 0), &attrs.into());
        // }

        // if the user wants to "truncate"
        if let Some(_size) = size {
            info!("truncate() called with {:?} {:?}", inode, size);
            // TODO: truncate using the length arg
            let blocks = inode.truncate();
            self.release_data_blocks(&blocks);
            let Ok(_)=self.save_inode(&mut inode, ino).map_err(|_| libc::EIO)else{
                reply.error(libc::EIO);
                return;
            };
        }

        // if user wants to change access time
        if let Some(atime) = atime {
            info!("utimens() called with {:?}, atime={:?}", inode, atime);
            if attrs.uid != req.uid() && req.uid() != 0 && atime != TimeOrNow::Now {
                reply.error(libc::EPERM);
                return;
            }

            if attrs.uid != req.uid() {
                reply.error(libc::EACCES);
                return;
            }

            inode.accessed_at = match atime {
                TimeOrNow::SpecificTime(time) => Some(time.try_into().unwrap()), // time_from_system_time(&time),
                TimeOrNow::Now => Some(now),
            };
            inode.metadata_changed_at = Some(now);
        }
        // if user wants to change modified time
        if let Some(mtime) = mtime {
            info!("utimens() called with {:?}, mtime={:?}", inode, mtime);

            if attrs.uid != req.uid() && req.uid() != 0 && mtime != TimeOrNow::Now {
                reply.error(libc::EPERM);
                return;
            }

            if attrs.uid != req.uid() {
                reply.error(libc::EACCES);
                return;
            }

            inode.modified_at = match mtime {
                TimeOrNow::SpecificTime(time) => Some(time.try_into().unwrap()), //time_from_system_time(&time),
                TimeOrNow::Now => Some(now),
            };
            inode.metadata_changed_at = Some(now);
        }

        self.save_inode(&mut inode, ino).unwrap();
        reply.attr(&Duration::new(0, 0), &inode.into());
    }

    // to read a dir
    fn readdir(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: fuser::ReplyDirectory,
    ) {
        info!("readdir() called with inode number: {ino}");
        if offset < 0 {
            reply.error(libc::EINVAL);
        } else {
            let Ok(dir) = self.find_dir_from_inode(ino) else{
                reply.error(libc::ENOENT);
                return;
            };
            for (index, entry) in dir.get_entries().iter().skip(offset as usize).enumerate() {
                let (name, inode_number) = entry;
                let inode = self.find_inode(*inode_number).unwrap();
                let buffer_full: bool = reply.add(
                    *inode_number,
                    offset + index as i64 + 1,
                    inode.file_kind.into(),
                    name,
                );

                if buffer_full {
                    break;
                }
            }
            reply.ok();
        }
    }
    // to create a dir
    fn mkdir(
        &mut self,
        req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        mode: u32,
        _umask: u32,
        reply: fuser::ReplyEntry,
    ) {
        info!("mkdir() called with parent inode number: {parent} and name: {name:?}");
        let Ok(mut parent_dir) = self.find_dir_from_inode(parent) else {
            reply.error(libc::EINVAL);
            return;
        };

        let Some(new_inode_index) = self.allocate_inode() else{
                reply.error(libc::ENOSPC);
                return;
        };

        parent_dir
            .get_entries_mut()
            .insert(name.to_os_string(), new_inode_index);

        let mut new_dir_inode = Inode::new(
            new_inode_index,
            FileKind::Directory,
            self.superblock().block_size,
        );
        new_dir_inode.mode = (libc::S_IFDIR | mode) as u16;
        new_dir_inode.hard_links = 2;
        new_dir_inode.user_id = req.uid();
        new_dir_inode.group_id = req.gid();

        let Some(data_block_index) = self.allocate_data_block() else{
                reply.error(libc::ENOSPC);
                return;
            };

        let mut dir = Directory::default();
        dir.get_entries_mut().insert(".".into(), new_inode_index);
        dir.get_entries_mut().insert("..".into(), parent);
        let Ok(_) = new_dir_inode
                .add_block(data_block_index, 0)
        else {
                reply.error(libc::EIO);
                return;
        };

        let Ok(_) = self.save_inode(&mut new_dir_inode, new_inode_index) else{
            reply.error(libc::EIO);
            return;
        };

        let Ok(_) = self.save_dir(dir, new_inode_index) else{
            reply.error(libc::EIO);
            return;
        };

        let Ok(_) = self.save_dir(parent_dir, parent) else{
            reply.error(libc::EIO);
            return;
        };
        // self.save_dir(dir, data_block_index)
        //     .map_err(|_| Errno::EIO)?;
        // self.save_dir(parent, parent_index)
        //     .map_err(|_| Errno::EIO)?;
        reply.entry(&Duration::new(0, 0), &new_dir_inode.into(), 0);
    }
    // to remove a dir
    fn rmdir(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        reply: fuser::ReplyEmpty,
    ) {
        info!("rmdir() called with parent inode number: {parent} and name: {name:?}");
        let Ok(mut parent_dir) = self.find_dir_from_inode(parent) else {
            reply.error(libc::EINVAL);
            return;
        };

        let Some(inode_index) = parent_dir.entry(name) else {
            reply.error(libc::ENOENT);
            return;
        };

        let Ok(inode) = self.find_inode(inode_index) else {
            reply.error(libc::ENOENT);
            return;
        };

        if !inode.is_dir() {
            reply.error(libc::ENOTDIR);
            return;
        }

        // if other inodes are pointing to this directory, we can't delete it
        if inode.hard_links > 2 {
            reply.error(libc::ENOTEMPTY);
            return;
        }

        parent_dir.entries.remove(name);
        self.release_inode(inode_index);
        self.release_data_blocks(&inode.direct_blocks());
        if inode.indirect_block != 0 {
            let Ok(_) = self.release_indirect_block(inode.indirect_block) else{
                reply.error(libc::EIO);
                return;
            };
        }
        if inode.double_indirect_block != 0 {
            let Ok(_) = self.release_double_indirect_block(inode.double_indirect_block) else{
                reply.error(libc::EIO);
                return;
            };
        }
        let Ok(_)= self.save_dir(parent_dir, parent) else {
            reply.error(libc::EIO);
            return;
        };
        reply.ok();
    }

    // read a symbolic link
    fn readlink(&mut self, _req: &fuser::Request<'_>, ino: u64, reply: fuser::ReplyData) {
        info!("readlink() called with inode number: {ino}");
        let Ok(mut inode) = self.find_inode(ino) else {
            reply.error(libc::ENOENT);
            return;
        };
        let mut offset = 0;
        let block_size = self.superblock().block_size;
        // Could underflow if file length is less than local_start
        let should_read = inode.file_size as usize;
        let mut total_read: usize = 0;
        let mut buf = vec![0u8; should_read];
        while total_read != should_read {
            let block_to_read_index = offset / block_size as u64;
            let Ok((block_index, space_left))= self.find_data_block(&mut inode, offset, true) else{
                reply.error(libc::EIO);
                return;
            };

            let max_read_len = buf.len().min(space_left as usize);
            let max_read_len = buf.len().min(max_read_len + total_read);

            let offset_in_block = if total_read != 0 {
                // it is not the first block to read
                0
            } else {
                // it is the first block to read
                offset - block_to_read_index * block_size as u64
            };

            let Ok(read) = self
                .read_data_from_data_block(
                    &mut buf[total_read..max_read_len],
                    offset_in_block,
                    block_index,
                )
            else{
                reply.error(libc::EIO);
                return;
            };
            total_read += read;
            offset += read as u64;
        }

        inode.update_accessed_at();
        let Ok(_) = self.save_inode(&mut inode, ino) else{
            reply.error(libc::EIO);
            return;
        };
        reply.data(&buf);
        println!("readlink() returning: {:#?}", OsString::from_vec(buf));
    }

    // create a symbolic link
    fn symlink(
        &mut self,
        req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        link: &std::path::Path,
        reply: fuser::ReplyEntry,
    ) {
        info!("symlink() called with parent inode number: {parent} and name: {name:?} and link: {link:?}");

        let Ok(mut parent_inode) = self.find_inode(parent) else {
            reply.error(libc::ENOENT);
            return;
        };
        let Ok(mut parent_dir) = self.find_dir_from_inode(parent) else {
            reply.error(libc::ENOENT);
            return;
        };

        let Some(symlink_inode_number) = self.allocate_inode() else {
            reply.error(libc::ENOSPC);
            return;
        };

        let mut symlink_inode = Inode::new(
            symlink_inode_number,
            FileKind::SymbolicLink,
            self.superblock().block_size,
        );
        symlink_inode.file_size = link.as_os_str().len() as u64;
        symlink_inode.user_id = req.uid();
        symlink_inode.group_id = req.gid();

        let Ok((symlink_block_number,_)) = self.find_data_block(&mut symlink_inode, 0, false) else{
            reply.error(libc::ENOSPC);
            return;
        };
        let Ok(_) = self.save_inode(&mut symlink_inode, symlink_inode_number) else{
            reply.error(libc::EIO);
            return;
        };
        let Ok(_) = self.write_data_to_data_block(link.as_os_str().as_bytes(), 0, symlink_block_number) else{
            reply.error(libc::EIO);
            return;
        };

        parent_dir
            .get_entries_mut()
            .insert(name.to_os_string(), symlink_inode_number);
        let Ok(_)=self.save_dir(parent_dir, parent) else{
            reply.error(libc::EIO);
            return;
        };

        parent_inode.update_modified_at();
        reply.entry(&Duration::new(0, 0), &symlink_inode.into(), 0);
    }

    // to look up a file
    fn lookup(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        reply: fuser::ReplyEntry,
    ) {
        info!("lookup() called with parent inode number: {parent} and name: {name:?}");
        let ttl = Duration::new(0, 0);
        let Ok(parent_dir) = self.find_dir_from_inode(parent) else {
            reply.error(libc::ENOENT);
            return;
        };
        if let Some(entry) = parent_dir.entry(name) {
            let name_inode = self.find_inode(entry).unwrap();
            reply.entry(&ttl, &name_inode.into(), 0);
        } else {
            reply.error(libc::ENOENT);
        }
    }

    // to create a new file
    fn create(
        &mut self,
        req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        mut mode: u32,
        _umask: u32,
        _flags: i32,
        reply: fuser::ReplyCreate,
    ) {
        info!("create() called with parent inode number: {parent} and name: {name:?}");
        let Ok(mut parent_dir) = self.find_dir_from_inode(parent) else {
                reply.error(libc::EINVAL);
                return;
        };
        if parent_dir.entry(name).is_some() {
            reply.error(libc::EEXIST);
            return;
        }

        // let (read, write) = match flags & libc::O_ACCMODE {
        //     libc::O_RDONLY => (true, false),
        //     libc::O_WRONLY => (false, true),
        //     libc::O_RDWR => (true, true),
        //     // Exactly one access mode flag must be specified
        //     _ => {
        //         reply.error(libc::EINVAL);
        //         return;
        //     }
        // };

        let Some(new_inode_index) = self.allocate_inode() else{
                reply.error(libc::ENOSPC);
                return;
        };

        parent_dir
            .get_entries_mut()
            .insert(name.to_os_string(), new_inode_index);

        let mut inode = Inode::new(
            new_inode_index,
            FileKind::RegularFile,
            self.superblock().block_size,
        );

        if req.uid() != 0 {
            mode &= !(libc::S_ISUID | libc::S_ISGID);
        }

        inode.mode = (libc::S_IFREG | mode) as u16;
        inode.hard_links = 1;
        inode.user_id = req.uid();
        inode.group_id = req.gid();

        let Ok(_) = self.save_inode(&mut inode, new_inode_index) else{
                reply.error(libc::EIO);
                return;
        };

        let Ok(_) = self.save_dir(parent_dir, parent) else{
                reply.error(libc::EIO);
                return;
            };
        reply.created(&Duration::new(0, 0), &inode.into(), 0, 0, 0);
    }

    // to delete a file
    fn unlink(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        reply: fuser::ReplyEmpty,
    ) {
        info!("unlink() called with parent inode number: {parent} and name: {name:?}");
        let Ok(mut parent_dir) = self.find_dir_from_inode(parent) else {
            reply.error(libc::EINVAL);
            return;
        };

        let Some(inode_index) = parent_dir.entry(name) else {
            reply.error(libc::ENOENT);
            return;
        };

        let Ok(mut inode) = self.find_inode(inode_index) else {
            reply.error(libc::ENOENT);
            return;
        };
        inode.hard_links -= 1;
        // no inodes are pointing to this file, so we can delete it,
        // and update the parent directory
        if inode.hard_links == 0 {
            self.release_inode(inode_index);
            self.release_data_blocks(&inode.direct_blocks());
            if inode.indirect_block != 0 {
                let Ok(_) = self.release_indirect_block(inode.indirect_block) else{
                    reply.error(libc::EIO);
                    return;
                };
            }
            if inode.double_indirect_block != 0 {
                let Ok(_) = self.release_double_indirect_block(inode.double_indirect_block) else{
                    reply.error(libc::EIO);
                    return;
                };
            }
            parent_dir.entries.remove(name);
            let Ok(_) = self.save_dir(parent_dir, parent) else {
                reply.error(libc::EIO);
                return;
            };
        }

        // whether `hard links` is 0 or not, we need to update the inode
        let Ok(_) =self.save_inode(&mut inode, inode_index) else {
                reply.error(libc::EIO);
                return;
            };
        reply.ok();
    }

    fn rename(
        &mut self,
        req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        newparent: u64,
        newname: &std::ffi::OsStr,
        flags: u32,
        reply: fuser::ReplyEmpty,
    ) {
        let mut old_parent_dir = match self.find_dir_from_inode(parent) {
            Ok(dir) => dir,
            Err(_) => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let mut old_parent_inode = match self.find_inode(parent) {
            Ok(inode) => inode,
            Err(_) => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        let child_inode_number = match old_parent_dir.entry(name) {
            Some(ino) => ino,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let mut child_inode = match self.find_inode(child_inode_number) {
            Ok(inode) => inode,
            Err(_) => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        // "Sticky bit" handling
        if old_parent_inode.mode & libc::S_ISVTX as u16 != 0
            && req.uid() != 0
            && req.uid() != old_parent_inode.user_id
            && req.uid() != child_inode.user_id
        {
            reply.error(libc::EACCES);
            return;
        }

        let mut new_parent_inode = match self.find_inode(newparent) {
            Ok(inode) => inode,
            Err(_) => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        let mut new_parent_dir = match self.find_dir_from_inode(newparent) {
            Ok(dir) => dir,
            Err(_) => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        // "Sticky bit" handling in new_parent
        if new_parent_inode.mode & libc::S_ISVTX as u16 != 0 {
            if let Some(new_name_inode_number) = new_parent_dir.entry(newname) {
                let new_name_inode = self.find_inode(new_name_inode_number);
                if let Ok(existing_inode) = new_name_inode.as_ref() {
                    if req.uid() != 0
                        && req.uid() != new_parent_inode.user_id
                        && req.uid() != existing_inode.user_id
                    {
                        reply.error(libc::EACCES);
                        return;
                    }
                }
            }
        }

        if flags & libc::RENAME_EXCHANGE != 0 {
            let Some(new_name_inode_number) = new_parent_dir.entry(newname) else{
                reply.error(libc::ENOENT);
                return;
            };

            let mut new_name_inode = match self.find_inode(new_name_inode_number) {
                Ok(inode) => inode,
                Err(_) => {
                    reply.error(libc::ENOENT);
                    return;
                }
            };

            let new_parent_dir_entries = new_parent_dir.get_entries_mut();
            new_parent_dir_entries.insert(newname.to_os_string(), child_inode_number);
            self.save_dir(new_parent_dir, newparent).unwrap();

            let old_parent_entries = old_parent_dir.get_entries_mut();
            old_parent_entries.insert(name.to_os_string(), new_name_inode.inode_number);
            self.save_dir(old_parent_dir, parent).unwrap();

            let current_time = Some(now());
            old_parent_inode.metadata_changed_at = current_time;
            old_parent_inode.modified_at = current_time;
            self.save_inode(&mut old_parent_inode, parent).unwrap();

            new_parent_inode.metadata_changed_at = current_time;
            new_parent_inode.modified_at = current_time;
            self.save_inode(&mut new_parent_inode, newparent).unwrap();

            child_inode.metadata_changed_at = current_time;
            self.save_inode(&mut child_inode, child_inode_number)
                .unwrap();

            new_name_inode.metadata_changed_at = current_time;
            self.save_inode(&mut new_name_inode, new_name_inode_number)
                .unwrap();
            // update child_inode .. if it is a directory
            if child_inode.is_dir() {
                let mut child_dir = self.find_dir_from_inode(child_inode_number).unwrap();
                child_dir.entries.insert("..".into(), newparent);
                self.save_dir(child_dir, child_inode_number).unwrap();
            }
            // update new_name_inode .. if it is a directory
            if new_name_inode.is_dir() {
                let mut new_inode_dir = self.find_dir_from_inode(new_name_inode_number).unwrap();
                new_inode_dir.entries.insert("..".into(), parent);
                self.save_dir(new_inode_dir, new_name_inode_number).unwrap();
            }

            reply.ok();
            return;
        }

        let new_name_inode_number = new_parent_dir.entry(newname).unwrap_or_default();

        let mut new_name_inode = {
            if new_name_inode_number == 0 {
                Err(libc::ENOENT)
            } else {
                let inode = self.find_inode(new_name_inode_number).unwrap();
                Ok(inode)
            }
        };
        // Only overwrite an existing directory if it's empty
        if let Ok(new_name_attrs) = new_name_inode.as_ref() {
            if new_name_attrs.is_dir()
                && self
                    .find_dir_from_inode(new_name_inode_number)
                    .map_or(0, |dir| dir.entries.len())
                    > 2
            {
                reply.error(libc::ENOTEMPTY);
                return;
            }
        }

        // If target already exists,decrement its hardlink count
        if let Ok(mut existing_inode_attrs) = new_name_inode.as_mut() {
            let mut dir = self.find_dir_from_inode(newparent).unwrap();
            dir.entries.remove(newname);
            self.save_dir(dir, newparent).unwrap();

            if existing_inode_attrs.is_dir() {
                existing_inode_attrs.hard_links = 0;
            } else {
                existing_inode_attrs.hard_links -= 1;
            }

            existing_inode_attrs.metadata_changed_at = Some(now());
            self.save_inode(existing_inode_attrs, new_name_inode_number)
                .unwrap();
        }

        let mut old_parent_dir = self.find_dir_from_inode(parent).unwrap();
        old_parent_dir.entries.remove(name);
        self.save_dir(old_parent_dir, parent).unwrap();

        let mut new_parent_dir = self.find_dir_from_inode(newparent).unwrap();
        new_parent_dir
            .entries
            .insert(newname.into(), child_inode_number);
        self.save_dir(new_parent_dir, newparent).unwrap();

        let current_time = Some(now());
        old_parent_inode.metadata_changed_at = current_time;
        old_parent_inode.modified_at = current_time;
        self.save_inode(&mut old_parent_inode, parent).unwrap();

        new_parent_inode.metadata_changed_at = current_time;
        new_parent_inode.modified_at = current_time;
        self.save_inode(&mut new_parent_inode, newparent).unwrap();

        child_inode.metadata_changed_at = current_time;
        self.save_inode(&mut child_inode, child_inode_number)
            .unwrap();

        if child_inode.is_dir() {
            let mut child_dir = self.find_dir_from_inode(child_inode_number).unwrap();
            child_dir.entries.insert("..".into(), newparent);
            self.save_dir(child_dir, child_inode_number).unwrap();
        }

        reply.ok();
    }
}

fn _get_groups(pid: u32) -> Vec<u32> {
    #[cfg(not(target_os = "macos"))]
    {
        let path = format!("/proc/{}/task/{}/status", pid, pid);
        let file = File::open(path).unwrap();
        for line in BufReader::new(file).lines() {
            let line = line.unwrap();
            if line.starts_with("Groups:") {
                return line["Groups: ".len()..]
                    .split(' ')
                    .filter(|x| !x.trim().is_empty())
                    .map(|x| x.parse::<u32>().unwrap())
                    .collect();
            }
        }
    }

    vec![]
}

#[cfg(test)]
mod tests {}
