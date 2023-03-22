use clap::Parser;

#[derive(Parser, Debug, PartialEq)]
#[command(author, version, about, long_about)]
pub enum MyFsCli {
    /// create a new file system
    Mkfs(MkfsArgs),
    /// register a filesystem to `FUSE` and mount it    #[command(subcommand)]
    Mount(MountArgs),
}
///make a new fs subcommand
#[derive(clap::Args, Debug, PartialEq)]
#[command(author, version, about = "make a new file system")]
pub struct MkfsArgs {
    /// the path of the file system image file
    #[clap(short = 'I', long)]
    pub image_file_path: String,
    /// the size of the file system
    #[clap(short, long)]
    pub size: u64,
    /// the inode count of the file system
    #[clap(short, long)]
    pub inode_count: u64,
    /// the block size of the file system
    #[clap(short, long)]
    pub block_size: u32,
    /// user password
    #[clap(short, long)]
    pub password: String,
}

/// mount a fs subcommand
#[derive(clap::Args, Debug, PartialEq)]
#[command(author, version, about = "mount a file system")]
pub struct MountArgs {
    /// the path of the file system image file
    #[clap(short = 'I', long)]
    pub image_file_path: String,
    /// the mount point of the file system
    #[clap(short, long)]
    pub mount_point: String,
    /// user password
    #[clap(short, long)]
    pub password: String,
}

/// test the `MyFsCli` struct
/// test `mkfs` subcommand
#[cfg(test)]
mod mkfs_parse_args_tests {
    use std::io::Cursor;

    use super::*;
    /// test short parameter form
    #[test]
    fn test_short_parameter_form() {
        let password = "123456\n".to_string();
        let mut cursor = Cursor::new(password);
        let password = rpassword::read_password_from_bufread(&mut cursor).unwrap();
        let args = MyFsCli::parse_from([
            "myfs",
            "mkfs",
            "-I",
            "test",
            "-s",
            "30",
            "-i",
            "3172",
            "-b",
            "512",
            "-p",
            password.as_str(),
        ]);
        assert_eq!(
            args,
            MyFsCli::Mkfs(MkfsArgs {
                image_file_path: "test".to_string(),
                size: 30,
                inode_count: 3172,
                block_size: 512,
                password,
            })
        );
    }
    /// test long parameter form
    #[test]
    fn test_long_parameter_form() {
        let image_file_path_name = concat!("--", "image-file-path");
        let password = "123456\n".to_string();
        let mut cursor = Cursor::new(password);
        let password = rpassword::read_password_from_bufread(&mut cursor).unwrap();
        let args = MyFsCli::parse_from([
            "myfs",
            "mkfs",
            image_file_path_name,
            "test",
            "--size",
            "30",
            "--inode-count",
            "3172",
            "--block-size",
            "512",
            "--password",
            password.as_str(),
        ]);
        assert_eq!(
            args,
            MyFsCli::Mkfs(MkfsArgs {
                image_file_path: "test".to_string(),
                size: 30,
                inode_count: 3172,
                block_size: 512,
                password,
            })
        );
    }
}

/// test the `MyFsCli` struct
/// test `mount` subcommand
#[cfg(test)]
mod mount_parse_args_tests {
    use std::io::Cursor;

    use super::*;
    /// test short parameter form
    #[test]
    fn test_short_parameter_form() {
        let password = "123456\n".to_string();
        let mut cursor = Cursor::new(password);
        let password = rpassword::read_password_from_bufread(&mut cursor).unwrap();
        let args = MyFsCli::parse_from([
            "myfs",
            "mount",
            "-I",
            "test",
            "-m",
            "test",
            "-p",
            password.as_str(),
        ]);
        assert_eq!(
            args,
            MyFsCli::Mount(MountArgs {
                image_file_path: "test".to_string(),
                mount_point: "test".to_string(),
                password,
            })
        );
    }
    /// test long parameter form
    #[test]
    fn test_long_parameter_form() {
        let image_file_path_name = concat!("--", "image-file-path");
        let password = "123456\n".to_string();
        let mut cursor = Cursor::new(password);
        let password = rpassword::read_password_from_bufread(&mut cursor).unwrap();
        let args = MyFsCli::parse_from([
            "myfs",
            "mount",
            image_file_path_name,
            "test",
            "--mount-point",
            "test",
            "--password",
            password.as_str(),
        ]);
        assert_eq!(
            args,
            MyFsCli::Mount(MountArgs {
                image_file_path: "test".to_string(),
                mount_point: "test".to_string(),
                password,
            })
        );
    }
}
