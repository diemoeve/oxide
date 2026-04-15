#[cfg(feature = "edr-evasion")]
pub mod peb;
#[cfg(all(target_os = "windows", feature = "edr-evasion"))]
pub mod etw;
#[cfg(all(target_os = "windows", feature = "edr-evasion"))]
pub mod amsi;
#[cfg(all(target_os = "windows", feature = "edr-evasion"))]
pub mod sandbox;

pub fn init() {
    #[cfg(all(target_os = "windows", feature = "edr-evasion"))]
    unsafe {
        // Filled in Task 6
    }
}
