use clap::Parser;

#[derive(Parser, Debug, PartialEq)]
#[command(author, version, about, long_about)]
pub enum MyFsCli {
    /// create a new file system
    Mkfs(MkfsArgs),
    /// register a filesystem to `FUSE` and mount it
    Mount(MountArgs),
    /// change user password
    ChangeUserPassword(ChangeUserPasswordArgs),
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
}

/// change user password struct
#[derive(clap::Args, Debug, PartialEq)]
#[command(author, version, about = "change user password")]
pub struct ChangeUserPasswordArgs {
    /// the user name
    #[clap(short = 'n', long)]
    pub user_name: String,
}

/// test the `MyFsCli` struct
/// test `mkfs` subcommand
#[cfg(test)]
mod mkfs_parse_args_tests {
    use super::*;
    /// test short parameter form
    #[test]
    fn test_short_parameter_form() {
        let args = MyFsCli::parse_from([
            "myfs", "mkfs", "-I", "test", "-s", "30", "-i", "3172", "-b", "512",
        ]);
        assert_eq!(
            args,
            MyFsCli::Mkfs(MkfsArgs {
                image_file_path: "test".to_string(),
                size: 30,
                inode_count: 3172,
                block_size: 512,
            })
        );
    }
    /// test long parameter form
    #[test]
    fn test_long_parameter_form() {
        let image_file_path_name_arg = concat!("--", "image-file-path");
        let args = MyFsCli::parse_from([
            "myfs",
            "mkfs",
            image_file_path_name_arg,
            "test",
            "--size",
            "30",
            "--inode-count",
            "3172",
            "--block-size",
            "512",
        ]);
        assert_eq!(
            args,
            MyFsCli::Mkfs(MkfsArgs {
                image_file_path: "test".to_string(),
                size: 30,
                inode_count: 3172,
                block_size: 512,
            })
        );
    }
}

/// test the `MyFsCli` struct
/// test `mount` subcommand
#[cfg(test)]
mod mount_parse_args_tests {

    use super::*;
    /// test short parameter form
    #[test]
    fn test_short_parameter_form() {
        let args = MyFsCli::parse_from(["myfs", "mount", "-I", "test", "-m", "test"]);
        assert_eq!(
            args,
            MyFsCli::Mount(MountArgs {
                image_file_path: "test".to_string(),
                mount_point: "test".to_string(),
            })
        );
    }
    /// test long parameter form
    #[test]
    fn test_long_parameter_form() {
        let image_file_path_arg = concat!("--", "image-file-path");
        let args = MyFsCli::parse_from([
            "myfs",
            "mount",
            image_file_path_arg,
            "test",
            "--mount-point",
            "test",
        ]);
        assert_eq!(
            args,
            MyFsCli::Mount(MountArgs {
                image_file_path: "test".to_string(),
                mount_point: "test".to_string(),
            })
        );
    }
}

/// test the `ChangeUserPasswordArgs` struct
#[cfg(test)]
mod change_user_password_parse_args_tests {
    use super::*;
    /// test short parameter form
    #[test]
    fn test_short_parameter_form() {
        let args = MyFsCli::parse_from(["myfs", "change-user-password", "-n", "test"]);
        assert_eq!(
            args,
            MyFsCli::ChangeUserPassword(ChangeUserPasswordArgs {
                user_name: "test".to_string(),
            })
        );
    }
    /// test long parameter form
    #[test]
    fn test_long_parameter_form() {
        let user_name_arg = concat!("--", "user-name");
        let args = MyFsCli::parse_from(["myfs", "change-user-password", user_name_arg, "test"]);
        assert_eq!(
            args,
            MyFsCli::ChangeUserPassword(ChangeUserPasswordArgs {
                user_name: "test".to_string(),
            })
        );
    }
}
