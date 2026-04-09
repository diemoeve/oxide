#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::*;

#[cfg(target_os = "macos")]
mod darwin;
#[cfg(target_os = "macos")]
pub use darwin::*;

pub struct SystemInfo {
    pub hwid: String,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub username: String,
    pub privileges: String,
    pub av: Vec<String>,
    pub exe_path: String,
}
