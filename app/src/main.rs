use clap::Parser;
use filesystem::cli_interface::MyFsCli;
/// a CLI interface to users to choose create our filesystem,
/// or register it to `FUSE` and mount it.
///
/// The latter will block the program until we umount our filesystem ourselves,
///
/// or specify `AutoUmount` when mounting this fs.
fn main() -> anyhow::Result<()> {
    env_logger::builder().format_timestamp_nanos().init();
    let args = MyFsCli::parse();
    //if it is a `mkfs` subcommand
    match args {
        MyFsCli::Mkfs(args) => {
            let new_user_password =
                rpassword::prompt_password("Please input a password for a new user: ")?;
            //create a new file system
            filesystem::mkfs::mkfs(
                args.image_file_path,
                args.size,
                args.inode_count,
                args.block_size,
                new_user_password,
            )?;
        }
        MyFsCli::Mount(args) => {
            //if it is a `mount` subcommand
            //register a filesystem to `FUSE` and mount it
            let user_password =
                rpassword::prompt_password("Please input a password for a new user: ")?;
            filesystem::mount::mount(args.image_file_path, args.mount_point, user_password)?;
        }
    }
    Ok(())
}
