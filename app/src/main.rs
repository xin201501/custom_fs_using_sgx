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
            //create a new file system
            filesystem::mkfs::mkfs(
                args.image_file_path,
                args.size,
                args.inode_count,
                args.block_size,
                args.password,
            )?;
        }
        MyFsCli::Mount(args) => {
            //if it is a `mount` subcommand
            //register a filesystem to `FUSE` and mount it
            filesystem::mount::mount(args.image_file_path, args.mount_point, args.password)?;
        }
    }
    Ok(())
}
