use serde::{Deserialize, Serialize};

/// an enum to describe the type of a file
#[derive(Serialize, Deserialize, Debug, Default, Copy, Clone, PartialEq)]
pub enum FileKind {
    /// an regular file
    RegularFile,
    /// a directory
    Directory,
    /// a symbolic link
    SymbolicLink,
    /// Unknown
    #[default]
    Unknown,
}

/// implement a trait to convert [FileKind] to [fuser::FileType]
impl From<FileKind> for fuser::FileType {
    fn from(kind: FileKind) -> Self {
        match kind {
            FileKind::RegularFile => fuser::FileType::RegularFile,
            FileKind::Directory => fuser::FileType::Directory,
            FileKind::SymbolicLink => fuser::FileType::Symlink,
            // Unknown Types are treated as regular files
            FileKind::Unknown => fuser::FileType::RegularFile,
        }
    }
}
