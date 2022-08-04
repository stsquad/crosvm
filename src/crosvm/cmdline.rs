// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        use std::net;

        use base::RawDescriptor;
        #[cfg(feature = "gpu")]
        use devices::virtio::GpuDisplayParameters;
        use devices::virtio::vhost::user::device::parse_wayland_sock;

        #[cfg(feature = "gpu")]
        use super::sys::config::parse_gpu_display_options;
        use super::sys::config::{
            parse_coiommu_params, VfioCommand, parse_vfio, parse_vfio_platform,
        };
        use super::config::SharedDir;
    }
}

use std::collections::BTreeMap;
use std::path::PathBuf;

#[cfg(all(feature = "gpu", feature = "virgl_renderer_next"))]
use super::sys::config::parse_gpu_render_server_options;
#[cfg(all(feature = "gpu", feature = "virgl_renderer_next"))]
use super::sys::GpuRenderServerParameters;

#[cfg(any(feature = "video-decoder", feature = "video-encoder"))]
use super::config::parse_video_options;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use arch::MsrConfig;
use arch::Pstore;
use arch::VcpuAffinity;
use argh::FromArgs;
use base::getpid;
use devices::virtio::block::block::DiskOption;
#[cfg(feature = "audio_cras")]
use devices::virtio::common_backend::Parameters as SndParameters;
use devices::virtio::vhost::user::device;
#[cfg(any(feature = "video-decoder", feature = "video-encoder"))]
use devices::virtio::VideoBackendType;
#[cfg(feature = "audio")]
use devices::Ac97Parameters;
use devices::SerialHardware;
use devices::SerialParameters;
use devices::StubPciParameters;
use hypervisor::ProtectionType;
use resources::AddressRange;
use vm_control::BatteryType;

#[cfg(feature = "gpu")]
use super::sys::config::parse_gpu_options;
#[cfg(feature = "audio")]
use crate::crosvm::config::parse_ac97_options;
use crate::crosvm::config::{
    numbered_disk_option, parse_battery_options, parse_bus_id_addr, parse_cpu_affinity,
    parse_cpu_capacity, parse_cpu_set, parse_file_backed_mapping, parse_mmio_address_range,
    parse_pstore, parse_serial_options, parse_stub_pci_parameters, Executable,
    FileBackedMappingParameters, TouchDeviceOption, VhostUserFsOption, VhostUserOption,
    VhostUserWlOption, VvuOption,
};
#[cfg(feature = "direct")]
use crate::crosvm::config::{
    parse_direct_io_options, parse_pcie_root_port_params, DirectIoOption,
    HostPcieRootPortParameters,
};
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use crate::crosvm::config::{parse_memory_region, parse_userspace_msr_options};
#[cfg(feature = "plugin")]
use crate::crosvm::config::{parse_plugin_mount_option, BindMount, GidMap};

#[derive(FromArgs)]
/// crosvm
pub struct CrosvmCmdlineArgs {
    #[argh(switch)]
    /// use extended exit status
    pub extended_status: bool,
    #[argh(option, default = r#"String::from("info")"#)]
    /// specify log level, eg "off", "error", "debug,disk=off", etc
    pub log_level: String,
    #[argh(switch)]
    /// disable output to syslog
    pub no_syslog: bool,
    #[argh(subcommand)]
    pub command: Command,
}

#[allow(clippy::large_enum_variant)]
#[derive(FromArgs)]
#[argh(subcommand)]
pub enum CrossPlatformCommands {
    Balloon(BalloonCommand),
    BalloonStats(BalloonStatsCommand),
    Battery(BatteryCommand),
    #[cfg(feature = "composite-disk")]
    CreateComposite(CreateCompositeCommand),
    CreateQcow2(CreateQcow2Command),
    Device(DeviceCommand),
    Disk(DiskCommand),
    MakeRT(MakeRTCommand),
    Resume(ResumeCommand),
    Run(RunCommand),
    Stop(StopCommand),
    Suspend(SuspendCommand),
    Powerbtn(PowerbtnCommand),
    Sleepbtn(SleepCommand),
    Gpe(GpeCommand),
    Usb(UsbCommand),
    Version(VersionCommand),
    Vfio(VfioCrosvmCommand),
}

#[allow(clippy::large_enum_variant)]
#[derive(argh_helpers::FlattenSubcommand)]
pub enum Command {
    CrossPlatform(CrossPlatformCommands),
    Sys(super::sys::cmdline::Commands),
}

#[derive(FromArgs)]
#[argh(subcommand, name = "balloon")]
/// Set balloon size of the crosvm instance to `SIZE` bytes
pub struct BalloonCommand {
    #[argh(positional, arg_name = "SIZE")]
    /// amount of bytes
    pub num_bytes: u64,
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[derive(argh::FromArgs)]
#[argh(subcommand, name = "balloon_stats")]
/// Prints virtio balloon statistics for a `VM_SOCKET`
pub struct BalloonStatsCommand {
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "battery")]
/// Modify battery
pub struct BatteryCommand {
    #[argh(positional, arg_name = "BATTERY_TYPE")]
    /// battery type
    pub battery_type: String,
    #[argh(positional)]
    /// battery property
    /// status | present | health | capacity | aconline
    pub property: String,
    #[argh(positional)]
    /// battery property target
    /// STATUS | PRESENT | HEALTH | CAPACITY | ACONLINE
    pub target: String,
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[cfg(feature = "composite-disk")]
#[derive(FromArgs)]
#[argh(subcommand, name = "create_composite")]
/// Create a new composite disk image file
pub struct CreateCompositeCommand {
    #[argh(positional, arg_name = "PATH")]
    /// image path
    pub path: String,
    #[argh(positional, arg_name = "LABEL:PARTITION")]
    /// partitions
    pub partitions: Vec<String>,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "create_qcow2")]
/// Create Qcow2 image given path and size
pub struct CreateQcow2Command {
    #[argh(positional, arg_name = "PATH")]
    /// path to the new qcow2 file to create
    pub file_path: String,
    #[argh(positional, arg_name = "SIZE")]
    /// desired size of the image in bytes; required if not using --backing-file
    pub size: Option<u64>,
    #[argh(option)]
    /// path to backing file; if specified, the image will be the same size as the backing file, and
    /// SIZE may not be specified
    pub backing_file: Option<String>,
}

#[derive(FromArgs)]
#[argh(subcommand)]
pub enum DiskSubcommand {
    Resize(ResizeDiskSubcommand),
}

#[derive(FromArgs)]
/// resize disk
#[argh(subcommand, name = "resize")]
pub struct ResizeDiskSubcommand {
    #[argh(positional, arg_name = "DISK_INDEX")]
    /// disk index
    pub disk_index: usize,
    #[argh(positional, arg_name = "NEW_SIZE")]
    /// new disk size
    pub disk_size: u64,
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "disk")]
/// Manage attached virtual disk devices
pub struct DiskCommand {
    #[argh(subcommand)]
    pub command: DiskSubcommand,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "make_rt")]
/// Enables real-time vcpu priority for crosvm instances started with `--delay-rt`
pub struct MakeRTCommand {
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "resume")]
/// Resumes the crosvm instance
pub struct ResumeCommand {
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "stop")]
/// Stops crosvm instances via their control sockets
pub struct StopCommand {
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "suspend")]
/// Suspends the crosvm instance
pub struct SuspendCommand {
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "powerbtn")]
/// Triggers a power button event in the crosvm instance
pub struct PowerbtnCommand {
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "sleepbtn")]
/// Triggers a sleep button event in the crosvm instance
pub struct SleepCommand {
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "gpe")]
/// Injects a general-purpose event into the crosvm instance
pub struct GpeCommand {
    #[argh(positional)]
    /// GPE #
    pub gpe: u32,
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "usb")]
/// Manage attached virtual USB devices.
pub struct UsbCommand {
    #[argh(subcommand)]
    pub command: UsbSubCommand,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "version")]
/// Show package version.
pub struct VersionCommand {}

#[derive(FromArgs)]
#[argh(subcommand, name = "add")]
/// ADD
pub struct VfioAddSubCommand {
    #[argh(positional)]
    /// path to host's vfio sysfs
    pub vfio_path: PathBuf,
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "remove")]
/// REMOVE
pub struct VfioRemoveSubCommand {
    #[argh(positional)]
    /// path to host's vfio sysfs
    pub vfio_path: PathBuf,
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[derive(FromArgs)]
#[argh(subcommand)]
pub enum VfioSubCommand {
    Add(VfioAddSubCommand),
    Remove(VfioRemoveSubCommand),
}

#[derive(FromArgs)]
#[argh(subcommand, name = "vfio")]
/// add/remove host vfio pci device into guest
pub struct VfioCrosvmCommand {
    #[argh(subcommand)]
    pub command: VfioSubCommand,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "device")]
/// Start a device process
pub struct DeviceCommand {
    #[argh(subcommand)]
    pub command: DeviceSubcommand,
}

#[derive(FromArgs)]
#[argh(subcommand)]
/// Cross-platform Devices
pub enum CrossPlatformDevicesCommands {
    Block(device::BlockOptions),
    Net(device::NetOptions),
}

#[derive(argh_helpers::FlattenSubcommand)]
pub enum DeviceSubcommand {
    CrossPlatform(CrossPlatformDevicesCommands),
    Sys(super::sys::cmdline::DevicesSubcommand),
}

#[derive(FromArgs)]
#[argh(subcommand)]
pub enum UsbSubCommand {
    Attach(UsbAttachCommand),
    Detach(UsbDetachCommand),
    List(UsbListCommand),
}

#[derive(FromArgs)]
/// Attach usb device
#[argh(subcommand, name = "attach")]
pub struct UsbAttachCommand {
    #[argh(
        positional,
        arg_name = "BUS_ID:ADDR:BUS_NUM:DEV_NUM",
        from_str_fn(parse_bus_id_addr)
    )]
    pub addr: (u8, u8, u16, u16),
    #[argh(positional)]
    /// usb device path
    pub dev_path: String,
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[derive(FromArgs)]
/// Detach usb device
#[argh(subcommand, name = "detach")]
pub struct UsbDetachCommand {
    #[argh(positional, arg_name = "PORT")]
    /// usb port
    pub port: u8,
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[derive(FromArgs)]
/// Detach usb device
#[argh(subcommand, name = "list")]
pub struct UsbListCommand {
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

/// Start a new crosvm instance
#[remain::sorted]
#[argh_helpers::pad_description_for_argh]
#[derive(FromArgs)]
#[argh(subcommand, name = "run")]
pub struct RunCommand {
    #[cfg(feature = "audio")]
    #[argh(
        option,
        from_str_fn(parse_ac97_options),
        arg_name = "[backend=BACKEND,capture=true,capture_effect=EFFECT,client_type=TYPE,shm-fd=FD,client-fd=FD,server-fd=FD]"
    )]
    /// comma separated key=value pairs for setting up Ac97 devices.
    /// Can be given more than once.
    /// Possible key values:
    ///     backend=(null, cras, vios) - Where to route the audio
    ///          device. If not provided, backend will default to
    ///          null. `null` for /dev/null, cras for CRAS server
    ///          and vios for VioS server.
    ///     capture - Enable audio capture
    ///     capture_effects - | separated effects to be enabled for
    ///         recording. The only supported effect value now is
    ///         EchoCancellation or aec.
    ///     client_type - Set specific client type for cras backend.
    ///     socket_type - Set specific socket type for cras backend.
    ///     server - The to the VIOS server (unix socket)
    pub ac97: Vec<Ac97Parameters>,
    #[argh(option, long = "acpi-table", arg_name = "PATH")]
    /// path to user provided ACPI table
    pub acpi_tables: Vec<PathBuf>,
    #[argh(option)]
    /// path to Android fstab
    pub android_fstab: Option<PathBuf>,
    #[argh(option, arg_name = "N", long = "balloon-bias-mib")]
    /// amount to bias balance of memory between host and guest as the balloon inflates, in mib.
    pub balloon_bias: Option<i64>,
    #[argh(option, arg_name = "PATH")]
    /// path for balloon controller socket.
    pub balloon_control: Option<PathBuf>,
    #[argh(option, from_str_fn(parse_battery_options))]
    /// comma separated key=value pairs for setting up battery
    /// device
    /// Possible key values:
    ///     type=goldfish - type of battery emulation, defaults to
    ///     goldfish
    pub battery: Option<BatteryType>,
    #[argh(option)]
    /// path to BIOS/firmware ROM
    pub bios: Option<PathBuf>,
    #[argh(option, arg_name = "CID")]
    /// context ID for virtual sockets.
    pub cid: Option<u64>,
    #[cfg(unix)]
    #[argh(
        option,
        arg_name = "unpin_policy=POLICY,unpin_interval=NUM,unpin_limit=NUM,unpin_gen_threshold=NUM",
        from_str_fn(parse_coiommu_params)
    )]
    /// comma separated key=value pairs for setting up coiommu
    /// devices.
    /// Possible key values:
    ///     unpin_policy=lru - LRU unpin policy.
    ///     unpin_interval=NUM - Unpin interval time in seconds.
    ///     unpin_limit=NUM - Unpin limit for each unpin cycle, in
    ///        unit of page count. 0 is invalid.
    ///     unpin_gen_threshold=NUM -  Number of unpin intervals a
    ///        pinned page must be busy for to be aged into the
    ///        older which is less frequently checked generation.
    pub coiommu: Option<devices::CoIommuParameters>,
    #[argh(
        option,
        arg_name = "CPU=CAP[,CPU=CAP[,...]]",
        from_str_fn(parse_cpu_capacity)
    )]
    /// set the relative capacity of the given CPU (default: no capacity)
    pub cpu_capacity: Option<BTreeMap<usize, u32>>, // CPU index -> capacity
    #[argh(
        option,
        long = "cpu-cluster",
        arg_name = "CPUSET",
        from_str_fn(parse_cpu_set)
    )]
    /// group the given CPUs into a cluster (default: no clusters)
    pub cpu_clusters: Vec<Vec<usize>>,
    #[cfg(feature = "audio_cras")]
    #[argh(
        option,
        arg_name = "[capture=true,client=crosvm,socket=unified,\
        num_output_devices=1,num_input_devices=1,num_output_streams=1,num_input_streams=1]",
        long = "cras-snd"
    )]
    /// comma separated key=value pairs for setting up virtio snd
    /// devices.
    /// Possible key values:
    ///     capture=(false,true) - Disable/enable audio capture.
    ///         Default is false.
    ///     client_type=(crosvm,arcvm,borealis) - Set specific
    ///         client type for cras backend. Default is crosvm.
    ///     socket_type=(legacy,unified) Set specific socket type
    ///         for cras backend. Default is unified.
    ///     num_output_devices=INT - Set number of output PCM
    ///         devices.
    ///     num_input_devices=INT - Set number of input PCM devices.
    ///     num_output_streams=INT - Set number of output PCM
    ///         streams per device.
    ///     num_input_streams=INT - Set number of input PCM streams
    ///         per device.
    pub cras_snds: Vec<SndParameters>,
    #[argh(switch)]
    /// don't set VCPUs real-time until make-rt command is run
    pub delay_rt: bool,
    #[cfg(feature = "direct")]
    #[argh(option, arg_name = "irq")]
    /// enable interrupt passthrough
    pub direct_edge_irq: Vec<u32>,
    #[cfg(feature = "direct")]
    #[argh(option, arg_name = "gpe")]
    /// enable GPE interrupt and register access passthrough
    pub direct_gpe: Vec<u32>,
    #[cfg(feature = "direct")]
    #[argh(option, arg_name = "irq")]
    /// enable interrupt passthrough
    pub direct_level_irq: Vec<u32>,
    #[cfg(feature = "direct")]
    #[argh(
        option,
        arg_name = "PATH@RANGE[,RANGE[,...]]",
        from_str_fn(parse_direct_io_options)
    )]
    /// path and ranges for direct memory mapped I/O access. RANGE may be decimal or hex (starting with 0x)
    pub direct_mmio: Option<DirectIoOption>,
    #[cfg(feature = "direct")]
    #[argh(
        option,
        arg_name = "PATH@RANGE[,RANGE[,...]]",
        from_str_fn(parse_direct_io_options)
    )]
    /// path and ranges for direct port mapped I/O access. RANGE may be decimal or hex (starting with 0x)
    pub direct_pmio: Option<DirectIoOption>,
    #[argh(switch)]
    /// run all devices in one, non-sandboxed process
    pub disable_sandbox: bool,
    #[argh(switch)]
    /// disable INTx in virtio devices
    pub disable_virtio_intx: bool,
    #[argh(
        option,
        short = 'd',
        long = "disk",
        arg_name = "PATH[,key=value[,key=value[,...]]",
        from_str_fn(numbered_disk_option)
    )]
    /// path to a disk image followed by optional comma-separated
    /// options.
    /// Valid keys:
    ///    sparse=BOOL - Indicates whether the disk should support
    ///        the discard operation (default: true)
    ///    block_size=BYTES - Set the reported block size of the
    ///        disk (default: 512)
    ///    id=STRING - Set the block device identifier to an ASCII
    ///        string, up to 20 characters (default: no ID)
    ///    o_direct=BOOL - Use O_DIRECT mode to bypass page cache"
    pub disks: Vec<(usize, DiskOption)>,
    #[argh(switch)]
    /// capture keyboard input from the display window
    pub display_window_keyboard: bool,
    #[argh(switch)]
    /// capture keyboard input from the display window
    pub display_window_mouse: bool,
    #[argh(option, long = "dmi", arg_name = "DIR")]
    /// directory with smbios_entry_point/DMI files
    pub dmi_path: Option<PathBuf>,
    #[argh(switch)]
    /// expose Power and Perfomance (PnP) data to guest and guest can show these PnP data
    pub enable_pnp_data: bool,
    #[argh(positional, arg_name = "KERNEL")]
    /// bzImage of kernel to run
    pub executable_path: Option<PathBuf>,
    #[argh(
        option,
        long = "file-backed-mapping",
        arg_name = "addr=NUM,size=SIZE,path=PATH[,offset=NUM][,ro][,rw][,sync]",
        from_str_fn(parse_file_backed_mapping)
    )]
    /// map the given file into guest memory at the specified
    /// address.
    /// Parameters (addr, size, path are required):
    ///     addr=NUM - guest physical address to map at
    ///     size=NUM - amount of memory to map
    ///     path=PATH - path to backing file/device to map
    ///     offset=NUM - offset in backing file (default 0)
    ///     ro - make the mapping readonly (default)
    ///     rw - make the mapping writable
    ///     sync - open backing file with O_SYNC
    ///     align - whether to adjust addr and size to page
    ///        boundaries implicitly
    pub file_backed_mappings: Vec<FileBackedMappingParameters>,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[argh(switch)]
    /// force use of a calibrated TSC cpuid leaf (0x15) even if the hypervisor
    /// doesn't require one.
    pub force_calibrated_tsc_leaf: bool,
    #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
    #[argh(option, arg_name = "PORT")]
    /// (EXPERIMENTAL) gdb on the given port
    pub gdb: Option<u32>,
    #[cfg(feature = "gpu")]
    #[argh(
        option,
        arg_name = "[width=INT,height=INT]",
        from_str_fn(parse_gpu_display_options)
    )]
    /// (EXPERIMENTAL) Comma separated key=value pairs for setting
    /// up a display on the virtio-gpu device
    /// Possible key values:
    ///     width=INT - The width of the virtual display connected
    ///        to the virtio-gpu.
    ///     height=INT - The height of the virtual display
    ///        connected to the virtio-gpu
    #[cfg(unix)]
    pub gpu_display: Vec<GpuDisplayParameters>,
    #[cfg(feature = "gpu")]
    #[argh(option, long = "gpu", from_str_fn(parse_gpu_options))]
    /// (EXPERIMENTAL) Comma separated key=value pairs for setting
    /// up a virtio-gpu device
    /// Possible key values:
    ///     backend=(2d|virglrenderer|gfxstream) - Which backend to
    ///        use for virtio-gpu (determining rendering protocol)
    ///     context-types=LIST - The list of supported context
    ///       types, separated by ':' (default: no contexts enabled)
    ///     width=INT - The width of the virtual display connected
    ///        to the virtio-gpu.
    ///     height=INT - The height of the virtual display
    ///        connected to the virtio-gpu.
    ///     egl[=true|=false] - If the backend should use a EGL
    ///        context for rendering.
    ///     glx[=true|=false] - If the backend should use a GLX
    ///        context for rendering.
    ///     surfaceless[=true|=false] - If the backend should use a
    ///         surfaceless context for rendering.
    ///     angle[=true|=false] - If the gfxstream backend should
    ///        use ANGLE (OpenGL on Vulkan) as its native OpenGL
    ///        driver.
    ///     syncfd[=true|=false] - If the gfxstream backend should
    ///        support EGL_ANDROID_native_fence_sync
    ///     vulkan[=true|=false] - If the backend should support
    ///        vulkan
    ///     wsi=vk - If the gfxstream backend should use the Vulkan
    ///        swapchain to draw on a window
    ///     cache-path=PATH - The path to the virtio-gpu device
    ///        shader cache.
    ///     cache-size=SIZE - The maximum size of the shader cache.
    ///     pci-bar-size=SIZE - The size for the PCI BAR in bytes
    ///        (default 8gb).
    pub gpu_params: Option<devices::virtio::GpuParameters>,
    #[cfg(all(unix, feature = "gpu", feature = "virgl_renderer_next"))]
    #[argh(option, from_str_fn(parse_gpu_render_server_options))]
    /// (EXPERIMENTAL) Comma separated key=value pairs for setting
    /// up a render server for the virtio-gpu device
    /// Possible key values:
    ///     path=PATH - The path to the render server executable.
    ///     cache-path=PATH - The path to the render server shader
    ///         cache.
    ///     cache-size=SIZE - The maximum size of the shader cache
    pub gpu_render_server: Option<GpuRenderServerParameters>,
    #[argh(switch)]
    /// use mirror cpu topology of Host for Guest VM, also copy some cpu feature to Guest VM
    pub host_cpu_topology: bool,
    #[cfg(unix)]
    #[argh(option, arg_name = "IP")]
    /// IP address to assign to host tap interface
    pub host_ip: Option<net::Ipv4Addr>,
    #[argh(switch)]
    /// advise the kernel to use Huge Pages for guest memory mappings
    pub hugepages: bool,
    #[argh(option, long = "init-mem", arg_name = "N")]
    /// amount of guest memory outside the balloon at boot in MiB. (default: --mem)
    pub init_memory: Option<u64>,
    #[argh(option, short = 'i', long = "initrd", arg_name = "PATH")]
    /// initial ramdisk to load
    pub initrd_path: Option<PathBuf>,
    #[argh(switch)]
    /// allow to enable ITMT scheduling feature in VM. The success of enabling depends on HWP and ACPI CPPC support on hardware
    pub itmt: bool,
    #[cfg(unix)]
    #[argh(option, long = "kvm-device", arg_name = "PATH")]
    /// path to the KVM device. (default /dev/kvm)
    pub kvm_device_path: Option<PathBuf>,
    #[cfg(unix)]
    #[argh(switch)]
    /// disable host swap on guest VM pages.
    pub lock_guest_memory: bool,
    #[cfg(unix)]
    #[argh(option, arg_name = "MAC", long = "mac")]
    /// MAC address for VM
    pub mac_address: Option<net_util::MacAddress>,
    #[argh(option, long = "mem", short = 'm', arg_name = "N")]
    /// amount of guest memory in MiB. (default: 256)
    pub memory: Option<u64>,
    #[argh(
        option,
        long = "mmio-address-range",
        from_str_fn(parse_mmio_address_range)
    )]
    /// MMIO address ranges
    pub mmio_address_ranges: Option<Vec<AddressRange>>,
    #[cfg(unix)]
    #[argh(option, arg_name = "N")]
    /// virtio net virtual queue pairs. (default: 1)
    pub net_vq_pairs: Option<u16>,
    #[cfg(unix)]
    #[argh(option, arg_name = "NETMASK")]
    /// netmask for VM subnet
    pub netmask: Option<net::Ipv4Addr>,
    #[argh(switch)]
    /// don't use virtio-balloon device in the guest
    pub no_balloon: bool,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[argh(switch)]
    /// don't use legacy KBD devices emulation
    pub no_i8042: bool,
    #[argh(switch)]
    /// don't create RNG device in the guest
    pub no_rng: bool,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[argh(switch)]
    /// don't use legacy RTC devices emulation
    pub no_rtc: bool,
    #[argh(switch)]
    /// don't use SMT in the guest
    pub no_smt: bool,
    #[argh(switch)]
    /// don't use usb devices in the guest
    pub no_usb: bool,
    #[argh(option, short = 'p', arg_name = "PARAMS")]
    /// extra kernel or plugin command line arguments. Can be given more than once
    pub params: Vec<String>,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[argh(option, long = "pci-start", arg_name = "pci_low_mmio_start")]
    /// the pci mmio start address below 4G
    pub pci_low_start: Option<u64>,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[argh(
        option,
        arg_name = "mmio_base,mmio_length",
        from_str_fn(parse_memory_region)
    )]
    /// region for PCIe Enhanced Configuration Access Mechanism
    pub pcie_ecam: Option<AddressRange>,
    #[cfg(feature = "direct")]
    #[argh(
        option,
        long = "pcie-root-port",
        arg_name = "PATH[,hp_gpe=NUM]",
        from_str_fn(parse_pcie_root_port_params)
    )]
    /// path to sysfs of host pcie root port and host pcie root port hotplug gpe number
    pub pcie_rp: Vec<HostPcieRootPortParameters>,
    #[argh(switch)]
    /// enable per-VM core scheduling intead of the default one (per-vCPU core scheduing) by
    /// making all vCPU threads share same cookie for core scheduling.
    /// This option is no-op on devices that have neither MDS nor L1TF vulnerability
    pub per_vm_core_scheduling: bool,
    #[argh(option, arg_name = "PATH")]
    /// path to empty directory to use for sandbox pivot root
    pub pivot_root: Option<PathBuf>,
    #[cfg(feature = "plugin")]
    #[argh(option, arg_name = "PATH")]
    /// absolute path to plugin process to run under crosvm
    pub plugin: Option<PathBuf>,
    #[cfg(feature = "plugin")]
    #[argh(option)]
    /// path to the file listing supplemental GIDs that should be mapped in plugin jail.  Can be given more than once
    pub plugin_gid_map_file: Option<PathBuf>,
    #[cfg(feature = "plugin")]
    #[argh(option, long = "plugin-gid-map", arg_name = "GID:GID:INT")]
    /// supplemental GIDs that should be mapped in plugin jail.  Can be given more than once
    pub plugin_gid_maps: Vec<GidMap>,
    #[cfg(feature = "plugin")]
    #[argh(option, arg_name = "PATH")]
    /// path to the file listing paths be mounted into the plugin's root filesystem.  Can be given more than once
    pub plugin_mount_file: Option<PathBuf>,
    #[cfg(feature = "plugin")]
    #[argh(option, long = "plugin-mount", arg_name = "PATH:PATH:BOOL")]
    /// path to be mounted into the plugin's root filesystem.  Can be given more than once
    pub plugin_mounts: Vec<BindMount>,
    #[cfg(feature = "plugin")]
    #[argh(option, arg_name = "PATH")]
    /// absolute path to a directory that will become root filesystem for the plugin process.
    pub plugin_root: Option<PathBuf>,
    #[argh(option, long = "pmem-device", arg_name = "PATH")]
    /// path to a disk image
    pub pmem_devices: Vec<DiskOption>,
    #[argh(switch)]
    /// grant this Guest VM certian privileges to manage Host resources, such as power management
    pub privileged_vm: bool,
    #[argh(switch)]
    /// prevent host access to guest memory
    pub protected_vm: bool,
    #[argh(switch)]
    /// (EXPERIMENTAL) prevent host access to guest memory, but don't use protected VM firmware
    protected_vm_without_firmware: bool,
    #[argh(option, arg_name = "path=PATH,size=SIZE", from_str_fn(parse_pstore))]
    /// path to pstore buffer backend file followed by size
    ///     [--pstore <path=PATH,size=SIZE>]
    pub pstore: Option<Pstore>,
    // Must be `Some` iff `protected_vm == ProtectionType::UnprotectedWithFirmware`.
    #[argh(option, long = "unprotected-vm-with-firmware", arg_name = "PATH")]
    /// (EXPERIMENTAL/FOR DEBUGGING) Use VM firmware, but allow host access to guest memory
    pub pvm_fw: Option<PathBuf>,
    #[argh(
        option,
        arg_name = "PATH[,key=value[,key=value[,...]]",
        short = 'r',
        from_str_fn(numbered_disk_option)
    )]
    /// path to a disk image followed by optional comma-separated
    /// options.
    /// Valid keys:
    ///     sparse=BOOL - Indicates whether the disk should support
    ///         the discard operation (default: true)
    ///     block_size=BYTES - Set the reported block size of the
    ///        disk (default: 512)
    ///     id=STRING - Set the block device identifier to an ASCII
    ///     string, up to 20 characters (default: no ID)
    ///     o_direct=BOOL - Use O_DIRECT mode to bypass page cache
    root: Option<(usize, DiskOption)>,
    #[argh(option, arg_name = "CPUSET", from_str_fn(parse_cpu_set))]
    /// comma-separated list of CPUs or CPU ranges to run VCPUs on. (e.g. 0,1-3,5) (default: none)
    pub rt_cpus: Option<Vec<usize>>,
    #[argh(option, long = "rw-pmem-device", arg_name = "PATH")]
    /// path to a writable disk image
    rw_pmem_devices: Vec<DiskOption>,
    #[argh(
        option,
        long = "rwdisk",
        arg_name = "PATH[,key=value[,key=value[,...]]",
        from_str_fn(numbered_disk_option)
    )]
    /// path to a read-write disk image followed by optional
    /// comma-separated options.
    /// Valid keys:
    ///     sparse=BOOL - Indicates whether the disk should support
    ///        the discard operation (default: true)
    ///     block_size=BYTES - Set the reported block size of the
    ///        disk (default: 512)
    ///     id=STRING - Set the block device identifier to an ASCII
    ///       string, up to 20 characters (default: no ID)
    ///     o_direct=BOOL - Use O_DIRECT mode to bypass page cache
    rwdisks: Vec<(usize, DiskOption)>,
    #[argh(
        option,
        arg_name = "PATH[,key=value[,key=value[,...]]",
        from_str_fn(numbered_disk_option)
    )]
    /// path to a read-write root disk image followed by optional
    /// comma-separated options.
    /// Valid keys:
    ///     sparse=BOOL - Indicates whether the disk should support
    ///       the discard operation (default: true)
    ///     block_size=BYTES - Set the reported block size of the
    ///        disk (default: 512)
    ///     id=STRING - Set the block device identifier to an ASCII
    ///        string, up to 20 characters (default: no ID)
    ///     o_direct=BOOL - Use O_DIRECT mode to bypass page cache
    rwroot: Option<(usize, DiskOption)>,
    #[argh(switch)]
    /// set Low Power S0 Idle Capable Flag for guest Fixed ACPI
    /// Description Table, additionally use enhanced crosvm suspend and resume
    /// routines to perform full guest suspension/resumption
    pub s2idle: bool,
    #[cfg(unix)]
    #[argh(switch)]
    /// instead of seccomp filter failures being fatal, they will be logged instead
    pub seccomp_log_failures: bool,
    #[cfg(unix)]
    #[argh(option, arg_name = "PATH")]
    /// path to seccomp .policy files
    pub seccomp_policy_dir: Option<PathBuf>,
    #[argh(
        option,
        long = "serial",
        arg_name = "type=TYPE,[hardware=HW,num=NUM,path=PATH,input=PATH,console,earlycon,stdin]",
        from_str_fn(parse_serial_options)
    )]
    /// comma separated key=value pairs for setting up serial
    /// devices. Can be given more than once.
    /// Possible key values:
    ///     type=(stdout,syslog,sink,file) - Where to route the
    ///        serial device
    ///     hardware=(serial,virtio-console) - Which type of serial
    ///        hardware to emulate. Defaults to 8250 UART (serial).
    ///     num=(1,2,3,4) - Serial Device Number. If not provided,
    ///        num will default to 1.
    ///     path=PATH - The path to the file to write to when
    ///        type=file
    ///     input=PATH - The path to the file to read from when not
    ///        stdin
    ///     console - Use this serial device as the guest console.
    ///        Can only be given once. Will default to first
    ///        serial port if not provided.
    ///     earlycon - Use this serial device as the early console.
    ///        Can only be given once.
    ///     stdin - Direct standard input to this serial device.
    ///        Can only be given once. Will default to first serial
    ///        port if not provided.
    pub serial_parameters: Vec<SerialParameters>,
    #[cfg(unix)]
    #[argh(
        option,
        long = "shared-dir",
        arg_name = "PATH:TAG[:type=TYPE:writeback=BOOL:timeout=SECONDS:uidmap=UIDMAP:gidmap=GIDMAP:cache=CACHE:dax=BOOL,posix_acl=BOOL]"
    )]
    /// colon-separated options for configuring a directory to be
    /// shared with the VM. The first field is the directory to be
    /// shared and the second field is the tag that the VM can use
    /// to identify the device. The remaining fields are key=value
    /// pairs that may appear in any order.
    ///  Valid keys are:
    ///     type=(p9, fs) - Indicates whether the directory should
    ///        be shared via virtio-9p or virtio-fs (default: p9).
    ///     uidmap=UIDMAP - The uid map to use for the device's
    ///        jail in the format "inner outer
    ///        count[,inner outer count]"
    ///        (default: 0 <current euid> 1).
    ///     gidmap=GIDMAP - The gid map to use for the device's
    ///        jail in the format "inner outer
    ///        count[,inner outer count]"
    ///        (default: 0 <current egid> 1).
    ///     cache=(never, auto, always) - Indicates whether the VM
    ///        can cache the contents of the shared directory
    ///        (default: auto).  When set to "auto" and the type
    ///        is "fs", the VM will use close-to-open consistency
    ///        for file contents.
    ///     timeout=SECONDS - How long the VM should consider file
    ///        attributes and directory entries to be valid
    ///        (default: 5).  If the VM has exclusive access to the
    ///        directory, then this should be a large value.  If
    ///        the directory can be modified by other processes,
    ///        then this should be 0.
    ///     writeback=BOOL - Enables writeback caching
    ///        (default: false).  This is only safe to do when the
    ///        VM has exclusive access to the files in a directory.
    ///        Additionally, the server should have read
    ///        permission for all files as the VM may issue read
    ///        requests even for files that are opened write-only.
    ///     dax=BOOL - Enables DAX support.  Enabling DAX can
    ///        improve performance for frequently accessed files
    ///        by mapping regions of the file directly into the
    ///        VM's memory. There is a cost of slightly increased
    ///        latency the first time the file is accessed.  Since
    ///        the mapping is shared directly from the host kernel's
    ///        file cache, enabling DAX can improve performance even
    ///         when the guest cache policy is "Never".  The default
    ///         value for this option is "false".
    ///     posix_acl=BOOL - Indicates whether the shared directory
    ///        supports POSIX ACLs.  This should only be enabled
    ///        when the underlying file system supports POSIX ACLs.
    ///        The default value for this option is "true".
    pub shared_dirs: Vec<SharedDir>,
    #[argh(option, short = 's', long = "socket", arg_name = "PATH")]
    /// path to put the control socket. If PATH is a directory, a name will be generated
    pub socket_path: Option<PathBuf>,
    #[cfg(feature = "tpm")]
    #[argh(switch)]
    /// enable a software emulated trusted platform module device
    pub software_tpm: bool,
    #[cfg(feature = "audio")]
    #[argh(option, arg_name = "PATH")]
    /// path to the VioS server socket for setting up virtio-snd devices
    pub sound: Option<PathBuf>,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[argh(switch)]
    /// (EXPERIMENTAL) enable split-irqchip support
    pub split_irqchip: bool,
    #[argh(switch)]
    /// don't allow guest to use pages from the balloon
    pub strict_balloon: bool,
    #[argh(
        option,
        long = "stub-pci-device",
        arg_name = "DOMAIN:BUS:DEVICE.FUNCTION[,vendor=NUM][,device=NUM][,class=NUM][,subsystem_vendor=NUM][,subsystem_device=NUM][,revision=NUM]",
        from_str_fn(parse_stub_pci_parameters)
    )]
    /// comma-separated key=value pairs for setting up a stub PCI
    /// device that just enumerates. The first option in the list
    /// must specify a PCI address to claim.
    /// Optional further parameters
    ///     vendor=NUM - PCI vendor ID
    ///     device=NUM - PCI device ID
    ///     class=NUM - PCI class (including class code, subclass,
    ///        and programming interface)
    ///     subsystem_vendor=NUM - PCI subsystem vendor ID
    ///     subsystem_device=NUM - PCI subsystem device ID
    ///     revision=NUM - revision
    pub stub_pci_devices: Vec<StubPciParameters>,
    #[argh(option, arg_name = "N")]
    /// (EXPERIMENTAL) Size of virtio swiotlb buffer in MiB (default: 64 if `--protected-vm` or `--protected-vm-without-firmware` is present)
    pub swiotlb: Option<u64>,
    #[argh(option, arg_name = "TAG")]
    /// when logging to syslog, use the provided tag
    pub syslog_tag: Option<String>,
    #[cfg(unix)]
    #[argh(option)]
    /// file descriptor for configured tap device. A different virtual network card will be added each time this argument is given
    pub tap_fd: Vec<RawDescriptor>,
    #[cfg(unix)]
    #[argh(option)]
    /// name of a configured persistent TAP interface to use for networking. A different virtual network card will be added each time this argument is given
    pub tap_name: Vec<String>,
    #[cfg(target_os = "android")]
    #[argh(option, arg_name = "NAME[,...]")]
    /// comma-separated names of the task profiles to apply to all threads in crosvm including the vCPU threads
    pub task_profiles: Vec<String>,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[argh(
        option,
        arg_name = "INDEX,type=TYPE,action=ACTION,[from=FROM],[filter=FILTER]",
        from_str_fn(parse_userspace_msr_options)
    )]
    /// userspace MSR handling. Takes INDEX of the MSR and how they
    ///  are handled.
    ///     type=(r|w|rw|wr) - read/write permission control.
    ///     action=(pass|emu) - if the control of msr is effective
    ///        on host.
    ///     from=(cpu0) - source of msr value. if not set, the
    ///        source is running CPU.
    ///     filter=(yes|no) - if the msr is filtered in KVM.
    pub userspace_msr: Vec<(u32, MsrConfig)>,
    #[argh(
        option,
        long = "cpu-affinity",
        arg_name = "CPUSET",
        from_str_fn(parse_cpu_affinity)
    )]
    /// comma-separated list of CPUs or CPU ranges to run VCPUs on (e.g. 0,1-3,5)
    /// or colon-separated list of assignments of guest to host CPU assignments (e.g. 0=0:1=1:2=2) (default: no mask)
    pub vcpu_affinity: Option<VcpuAffinity>,
    #[argh(option, arg_name = "PATH")]
    /// move all vCPU threads to this CGroup (default: nothing moves)
    pub vcpu_cgroup_path: Option<PathBuf>,
    #[argh(option, long = "cpus", short = 'c')]
    /// number of VCPUs. (default: 1)
    pub vcpu_count: Option<usize>,
    #[cfg(unix)]
    #[argh(
        option,
        arg_name = "PATH[,guest-address=auto|<BUS:DEVICE.FUNCTION>][,iommu=on|off]",
        from_str_fn(parse_vfio)
    )]
    /// path to sysfs of PCI pass through or mdev device.
    ///     guest-address=auto|<BUS:DEVICE.FUNCTION> - PCI address
    ///        that the device will be assigned in the guest
    ///        (default: auto).  When set to "auto", the device will
    ///        be assigned an address that mirrors its address in
    ///        the host.
    ///     iommu=on|off - indicates whether to enable virtio IOMMU
    ///        for this device
    pub vfio: Vec<VfioCommand>,
    #[cfg(unix)]
    #[argh(option, arg_name = "PATH", from_str_fn(parse_vfio_platform))]
    /// path to sysfs of platform pass through
    pub vfio_platform: Vec<VfioCommand>,
    #[argh(switch)]
    /// use vhost for networking
    pub vhost_net: bool,
    #[cfg(unix)]
    #[argh(option, long = "vhost-net-device", arg_name = "PATH")]
    /// path to the vhost-net device. (default /dev/vhost-net)
    pub vhost_net_device_path: Option<PathBuf>,
    #[argh(option, arg_name = "SOCKET_PATH")]
    /// path to a socket for vhost-user block
    pub vhost_user_blk: Vec<VhostUserOption>,
    #[argh(option, arg_name = "SOCKET_PATH")]
    /// path to a socket for vhost-user console
    pub vhost_user_console: Vec<VhostUserOption>,
    #[argh(option, arg_name = "SOCKET_PATH:TAG")]
    /// path to a socket path for vhost-user fs, and tag for the shared dir
    pub vhost_user_fs: Vec<VhostUserFsOption>,
    #[argh(option, arg_name = "SOCKET_PATH")]
    /// paths to a vhost-user socket for gpu
    pub vhost_user_gpu: Vec<VhostUserOption>,
    #[argh(option, arg_name = "SOCKET_PATH")]
    /// path to a socket for vhost-user mac80211_hwsim
    pub vhost_user_mac80211_hwsim: Option<VhostUserOption>,
    #[argh(option, arg_name = "SOCKET_PATH")]
    /// path to a socket for vhost-user net
    pub vhost_user_net: Vec<VhostUserOption>,
    #[argh(option, arg_name = "SOCKET_PATH")]
    /// path to a socket for vhost-user rng
    pub vhost_user_rng: Vec<VhostUserOption>,
    #[cfg(feature = "audio")]
    #[argh(option, arg_name = "SOCKET_PATH")]
    /// path to a socket for vhost-user snd
    pub vhost_user_snd: Vec<VhostUserOption>,
    #[argh(option, arg_name = "SOCKET_PATH")]
    /// path to a socket for vhost-user vsock
    pub vhost_user_vsock: Vec<VhostUserOption>,
    #[argh(option, arg_name = "SOCKET_PATH:TUBE_PATH")]
    /// paths to a vhost-user socket for wayland and a Tube socket for additional wayland-specific messages
    pub vhost_user_wl: Vec<VhostUserWlOption>,
    #[cfg(unix)]
    #[argh(option, arg_name = "SOCKET_PATH")]
    /// path to a socket for vhost-user vsock
    pub vhost_vsock_device: Option<PathBuf>,
    #[cfg(unix)]
    #[argh(option, arg_name = "FD")]
    /// open FD to the vhost-vsock device, mutually exclusive with vhost-vsock-device
    pub vhost_vsock_fd: Option<RawDescriptor>,
    #[cfg(feature = "video-decoder")]
    #[argh(
        option,
        long = "video-decoder",
        arg_name = "[backend]",
        from_str_fn(parse_video_options)
    )]
    /// (EXPERIMENTAL) enable virtio-video decoder device
    /// Possible backend values: libvda, ffmpeg, vaapi
    pub video_dec: Option<VideoBackendType>,
    #[cfg(feature = "video-encoder")]
    #[argh(
        option,
        long = "video-encoder",
        arg_name = "[backend]",
        from_str_fn(parse_video_options)
    )]
    /// (EXPERIMENTAL) enable virtio-video encoder device
    /// Possible backend values: libvda
    pub video_enc: Option<VideoBackendType>,
    #[argh(option, long = "evdev", arg_name = "PATH")]
    /// path to an event device node. The device will be grabbed (unusable from the host) and made available to the guest with the same configuration it shows on the host
    pub virtio_input_evdevs: Vec<PathBuf>,
    #[argh(option, long = "keyboard", arg_name = "PATH")]
    /// path to a socket from where to read keyboard input events and write status updates to
    pub virtio_keyboard: Vec<PathBuf>,
    #[argh(option, long = "mouse", arg_name = "PATH")]
    /// path to a socket from where to read mouse input events and write status updates to
    pub virtio_mice: Vec<PathBuf>,
    #[argh(option, long = "multi-touch", arg_name = "PATH:WIDTH:HEIGHT")]
    /// path to a socket from where to read multi touch input events (such as those from a touchscreen) and write status updates to, optionally followed by width and height (defaults to 800x1280)
    pub virtio_multi_touch: Vec<TouchDeviceOption>,
    #[argh(option, long = "single-touch", arg_name = "PATH:WIDTH:HEIGHT")]
    /// path to a socket from where to read single touch input events (such as those from a touchscreen) and write status updates to, optionally followed by width and height (defaults to 800x1280)
    pub virtio_single_touch: Vec<TouchDeviceOption>,
    #[cfg(feature = "audio_cras")]
    #[argh(
        option,
        arg_name = "[capture=true,backend=BACKEND,num_output_devices=1,
        num_input_devices=1,num_output_streams=1,num_input_streams=1]",
        long = "virtio-snd"
    )]
    /// comma separated key=value pairs for setting up virtio snd
    /// devices.
    /// Possible key values:
    ///     capture=(false,true) - Disable/enable audio capture.
    ///         Default is false.
    ///     backend=(null,[cras]) - Which backend to use for
    ///         virtio-snd.
    ///     client_type=(crosvm,arcvm,borealis) - Set specific
    ///         client type for cras backend. Default is crosvm.
    ///     socket_type=(legacy,unified) Set specific socket type
    ///         for cras backend. Default is unified.
    ///     num_output_devices=INT - Set number of output PCM
    ///         devices.
    ///     num_input_devices=INT - Set number of input PCM devices.
    ///     num_output_streams=INT - Set number of output PCM
    ///         streams per device.
    ///     num_input_streams=INT - Set number of input PCM streams
    ///         per device.
    pub virtio_snds: Vec<SndParameters>,
    #[argh(option, long = "switches", arg_name = "PATH")]
    /// path to a socket from where to read switch input events and write status updates to
    pub virtio_switches: Vec<PathBuf>,
    #[argh(option, long = "trackpad", arg_name = "PATH:WIDTH:HEIGHT")]
    /// path to a socket from where to read trackpad input events and write status updates to, optionally followed by screen width and height (defaults to 800x1280)
    pub virtio_trackpad: Vec<TouchDeviceOption>,
    #[cfg(all(feature = "tpm", feature = "chromeos", target_arch = "x86_64"))]
    #[argh(switch)]
    /// enable the virtio-tpm connection to vtpm daemon
    pub vtpm_proxy: bool,
    #[argh(
        option,
        arg_name = "SOCKET_PATH[,addr=DOMAIN:BUS:DEVICE.FUNCTION,uuid=UUID]"
    )]
    /// socket path for the Virtio Vhost User proxy device.
    /// Parameters
    ///     addr=BUS:DEVICE.FUNCTION - PCI address that the proxy
    ///        device will be allocated
    ///        (default: automatically allocated)
    ///     uuid=UUID - UUID which will be stored in VVU PCI config
    ///        space that is readable from guest userspace
    pub vvu_proxy: Vec<VvuOption>,
    #[cfg(unix)]
    #[argh(
        option,
        long = "wayland-sock",
        arg_name = "PATH[,name=NAME]",
        from_str_fn(parse_wayland_sock)
    )]
    /// path to the Wayland socket to use. The unnamed one is used for displaying virtual screens. Named ones are only for IPC
    pub wayland_socket_paths: Vec<(String, PathBuf)>,
    #[argh(option, arg_name = "DISPLAY")]
    /// X11 display name to use
    pub x_display: Option<String>,
}

impl TryFrom<RunCommand> for super::config::Config {
    type Error = String;

    fn try_from(cmd: RunCommand) -> Result<Self, Self::Error> {
        let mut cfg = Self::default();
        // TODO: we need to factor out some(?) of the checks into config::validate_config

        // Process arguments
        if let Some(p) = cmd.executable_path {
            cfg.executable_path = Some(Executable::Kernel(p));
        }

        #[cfg(unix)]
        if let Some(p) = cmd.kvm_device_path {
            cfg.kvm_device_path = p;
        }

        #[cfg(unix)]
        if let Some(p) = cmd.vhost_net_device_path {
            if !p.exists() {
                return Err(format!("vhost-net-device path {:?} does not exist", p));
            }
            cfg.vhost_net_device_path = p;
        }

        if let Some(p) = cmd.android_fstab {
            if !p.exists() {
                return Err(format!("android-fstab path {:?} does not exist", p));
            }
            cfg.android_fstab = Some(p);
        }

        cfg.params.extend(cmd.params);

        cfg.per_vm_core_scheduling = cmd.per_vm_core_scheduling;

        cfg.vcpu_count = cmd.vcpu_count;

        cfg.vcpu_affinity = cmd.vcpu_affinity;

        cfg.cpu_clusters = cmd.cpu_clusters;

        if let Some(capacity) = cmd.cpu_capacity {
            cfg.cpu_capacity = capacity;
        }

        cfg.vcpu_cgroup_path = cmd.vcpu_cgroup_path;

        cfg.no_smt = cmd.no_smt;

        if let Some(rt_cpus) = cmd.rt_cpus {
            cfg.rt_cpus = rt_cpus;
        }

        cfg.delay_rt = cmd.delay_rt;

        cfg.memory = cmd.memory;

        #[cfg(target_arch = "aarch64")]
        {
            cfg.swiotlb = cmd.swiotlb;
        }

        cfg.hugepages = cmd.hugepages;

        #[cfg(unix)]
        {
            cfg.lock_guest_memory = cmd.lock_guest_memory;
        }

        #[cfg(feature = "audio")]
        {
            cfg.ac97_parameters = cmd.ac97;
            cfg.sound = cmd.sound;
            cfg.vhost_user_snd = cmd.vhost_user_snd;
        }

        for serial_params in cmd.serial_parameters {
            super::sys::config::check_serial_params(&serial_params)?;

            let num = serial_params.num;
            let key = (serial_params.hardware, num);

            if cfg.serial_parameters.contains_key(&key) {
                return Err(format!(
                    "serial hardware {} num {}",
                    serial_params.hardware, num,
                ));
            }

            if serial_params.console {
                for params in cfg.serial_parameters.values() {
                    if params.console {
                        return Err(format!(
                            "{} device {} already set as console",
                            params.hardware, params.num,
                        ));
                    }
                }
            }

            if serial_params.earlycon {
                // Only SerialHardware::Serial supports earlycon= currently.
                match serial_params.hardware {
                    SerialHardware::Serial => {}
                    _ => {
                        return Err(super::config::invalid_value_err(
                            serial_params.hardware.to_string(),
                            String::from("earlycon not supported for hardware"),
                        ));
                    }
                }
                for params in cfg.serial_parameters.values() {
                    if params.earlycon {
                        return Err(format!(
                            "{} device {} already set as earlycon",
                            params.hardware, params.num,
                        ));
                    }
                }
            }

            if serial_params.stdin {
                if let Some(previous_stdin) = cfg.serial_parameters.values().find(|sp| sp.stdin) {
                    return Err(format!(
                        "{} device {} already connected to standard input",
                        previous_stdin.hardware, previous_stdin.num,
                    ));
                }
            }

            cfg.serial_parameters.insert(key, serial_params);
        }

        if cmd.root.is_some() && cmd.rwroot.is_some() {
            return Err("Only one of [root,rwroot] has to be specified".to_string());
        }

        let root_disk = if let Some((read_only, (index, mut disk_option))) = cmd
            .root
            .map(|d| (true, d))
            .or(cmd.rwroot.map(|d| (false, d)))
        {
            if index >= 26 {
                return Err("ran out of letters for to assign to root disk".to_string());
            }
            disk_option.read_only = read_only;

            cfg.params.push(format!(
                "root=/dev/vd{} {}",
                char::from(b'a' + index as u8),
                if read_only { "ro" } else { "rw" }
            ));
            Some((index, disk_option))
        } else {
            None
        };

        let mut disks = root_disk
            .into_iter()
            .chain(cmd.disks.into_iter().map(|(i, mut d)| {
                d.read_only = true;
                (i, d)
            }))
            .chain(cmd.rwdisks.into_iter().map(|(i, mut d)| {
                d.read_only = false;
                (i, d)
            }))
            .collect::<Vec<_>>();
        disks.sort_by_key(|(i, _)| *i);
        cfg.disks = disks.into_iter().map(|(_, d)| d).collect();

        for (mut pmem, read_only) in cmd
            .pmem_devices
            .into_iter()
            .map(|p| (p, true))
            .chain(cmd.rw_pmem_devices.into_iter().map(|p| (p, false)))
        {
            pmem.read_only = read_only;
            cfg.pmem_devices.push(pmem);
        }

        cfg.pstore = cmd.pstore;

        #[cfg(unix)]
        for (name, params) in cmd.wayland_socket_paths {
            if cfg.wayland_socket_paths.contains_key(&name) {
                return Err(format!("wayland socket name already used: '{}'", name));
            }
            cfg.wayland_socket_paths.insert(name, params);
        }

        cfg.x_display = cmd.x_display;

        cfg.display_window_keyboard = cmd.display_window_keyboard;
        cfg.display_window_mouse = cmd.display_window_mouse;

        if let Some(mut socket_path) = cmd.socket_path {
            if socket_path.is_dir() {
                socket_path.push(format!("crosvm-{}.sock", getpid()));
            }
            cfg.socket_path = Some(socket_path);
        }

        cfg.balloon_control = cmd.balloon_control;

        cfg.cid = cmd.cid;

        #[cfg(feature = "plugin")]
        {
            use std::fs::File;
            use std::io::BufRead;
            use std::io::BufReader;

            if let Some(p) = cmd.plugin {
                if cfg.executable_path.is_some() {
                    return Err(format!(
                        "A VM executable was already specified: {:?}",
                        cfg.executable_path
                    ));
                }
                cfg.executable_path = Some(Executable::Plugin(p));
            }
            cfg.plugin_root = cmd.plugin_root;
            cfg.plugin_mounts = cmd.plugin_mounts;

            if let Some(path) = cmd.plugin_mount_file {
                let file = File::open(path)
                    .map_err(|_| String::from("unable to open `plugin-mount-file` file"))?;
                let reader = BufReader::new(file);
                for l in reader.lines() {
                    let line = l.unwrap();
                    let trimmed_line = line.split_once('#').map_or(&*line, |x| x.0).trim();
                    if !trimmed_line.is_empty() {
                        let mount = parse_plugin_mount_option(trimmed_line)?;
                        cfg.plugin_mounts.push(mount);
                    }
                }
            }

            cfg.plugin_gid_maps = cmd.plugin_gid_maps;

            if let Some(path) = cmd.plugin_gid_map_file {
                let file = File::open(path)
                    .map_err(|_| String::from("unable to open `plugin-gid-map-file` file"))?;
                let reader = BufReader::new(file);
                for l in reader.lines() {
                    let line = l.unwrap();
                    let trimmed_line = line.split_once('#').map_or(&*line, |x| x.0).trim();
                    if !trimmed_line.is_empty() {
                        let map = trimmed_line.parse()?;
                        cfg.plugin_gid_maps.push(map);
                    }
                }
            }
        }

        cfg.vhost_net = cmd.vhost_net;

        #[cfg(feature = "tpm")]
        {
            cfg.software_tpm = cmd.software_tpm;
        }

        #[cfg(all(feature = "tpm", feature = "chromeos", target_arch = "x86_64"))]
        {
            cfg.vtpm_proxy = cmd.vtpm_proxy;
        }

        cfg.virtio_single_touch = cmd.virtio_single_touch;
        cfg.virtio_multi_touch = cmd.virtio_multi_touch;
        cfg.virtio_trackpad = cmd.virtio_trackpad;
        cfg.virtio_mice = cmd.virtio_mice;
        cfg.virtio_keyboard = cmd.virtio_keyboard;
        cfg.virtio_switches = cmd.virtio_switches;
        cfg.virtio_input_evdevs = cmd.virtio_input_evdevs;

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            cfg.split_irqchip = cmd.split_irqchip;
        }

        cfg.initrd_path = cmd.initrd_path;

        if cmd.disable_sandbox {
            cfg.jail_config = None;
        }

        if let Some(p) = cmd.bios {
            if cfg.executable_path.is_some() {
                return Err(format!(
                    "A VM executable was already specified: {:?}",
                    cfg.executable_path
                ));
            }
            cfg.executable_path = Some(Executable::Bios(p));
        }

        #[cfg(feature = "video-decoder")]
        {
            cfg.video_dec = cmd.video_dec;
        }
        #[cfg(feature = "video-encoder")]
        {
            cfg.video_enc = cmd.video_enc;
        }

        cfg.acpi_tables = cmd.acpi_tables;

        cfg.usb = !cmd.no_usb;
        cfg.rng = !cmd.no_rng;
        cfg.balloon = !cmd.no_balloon;

        #[cfg(feature = "audio_cras")]
        {
            cfg.virtio_snds = cmd.virtio_snds;
            // cmd.cras_snds is the old parameter for virtio snd with cras backend.
            // backend is assigned by Parameters Default implementation
            cfg.virtio_snds.extend_from_slice(&cmd.cras_snds);
        }

        #[cfg(feature = "gpu")]
        {
            cfg.gpu_parameters = cmd.gpu_params;
        }

        #[cfg(unix)]
        {
            if cmd.vhost_vsock_device.is_some() && cmd.vhost_vsock_fd.is_some() {
                return Err(
                    "Only one of vhost-vsock-device vhost-vsock-fd has to be specified".to_string(),
                );
            }

            cfg.vhost_vsock_device = cmd.vhost_vsock_device;

            if let Some(fd) = cmd.vhost_vsock_fd {
                cfg.vhost_vsock_device = Some(PathBuf::from(format!("/proc/self/fd/{}", fd)));
            }

            cfg.shared_dirs = cmd.shared_dirs;

            cfg.host_ip = cmd.host_ip;
            cfg.netmask = cmd.netmask;
            cfg.mac_address = cmd.mac_address;

            cfg.tap_name = cmd.tap_name;
            cfg.tap_fd = cmd.tap_fd;

            cfg.coiommu_param = cmd.coiommu;

            #[cfg(all(feature = "gpu", feature = "virgl_renderer_next"))]
            {
                cfg.gpu_render_server_parameters = cmd.gpu_render_server;
            }

            if let Some(d) = cmd.seccomp_policy_dir {
                cfg.jail_config
                    .get_or_insert_with(Default::default)
                    .seccomp_policy_dir = Some(d);
            }

            if cmd.seccomp_log_failures {
                cfg.jail_config
                    .get_or_insert_with(Default::default)
                    .seccomp_log_failures = true;
            }

            if let Some(p) = cmd.pivot_root {
                cfg.jail_config
                    .get_or_insert_with(Default::default)
                    .pivot_root = p;
            }

            #[cfg(feature = "gpu")]
            {
                if !cmd.gpu_display.is_empty() {
                    cfg.gpu_parameters
                        .get_or_insert_with(Default::default)
                        .displays
                        .extend(cmd.gpu_display);
                }
            }

            cfg.net_vq_pairs = cmd.net_vq_pairs;
        }

        if cmd.protected_vm && cmd.protected_vm_without_firmware && cmd.pvm_fw.is_some() {
            return Err("Only one protection mode has to be specified".to_string());
        }

        if cmd.protected_vm {
            cfg.protected_vm = ProtectionType::Protected;
            // Balloon and USB devices only work for unprotected VMs.
            cfg.balloon = false;
            cfg.usb = false;
            // Protected VMs can't trust the RNG device, so don't provide it.
            cfg.rng = false;
        } else if cmd.protected_vm_without_firmware {
            cfg.protected_vm = ProtectionType::ProtectedWithoutFirmware;
            // Balloon and USB devices only work for unprotected VMs.
            cfg.balloon = false;
            cfg.usb = false;
            // Protected VMs can't trust the RNG device, so don't provide it.
            cfg.rng = false;
        } else if let Some(p) = cmd.pvm_fw {
            if !p.exists() || !p.is_file() {
                return Err(
                    "unprotected-vm-with-firmware path should be an existing file".to_string(),
                );
            }
            cfg.protected_vm = ProtectionType::Unprotected;
            // Balloon and USB devices only work for unprotected VMs.
            cfg.balloon = false;
            cfg.usb = false;
            // Protected VMs can't trust the RNG device, so don't provide it.
            cfg.rng = false;
            cfg.pvm_fw = Some(p);
        }

        cfg.battery_type = cmd.battery;

        #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
        {
            cfg.gdb = cmd.gdb;
        }

        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        {
            cfg.host_cpu_topology = cmd.host_cpu_topology;
            cfg.force_s2idle = cmd.s2idle;
            cfg.pcie_ecam = cmd.pcie_ecam;
            cfg.pci_low_start = cmd.pci_low_start;
            cfg.no_i8042 = cmd.no_i8042;
            cfg.no_rtc = cmd.no_rtc;

            for (index, msr_config) in cmd.userspace_msr {
                if cfg.userspace_msr.insert(index, msr_config).is_some() {
                    return Err(String::from("msr must be unique"));
                }
            }
        }

        // cfg.balloon_bias is in bytes.
        if let Some(b) = cmd.balloon_bias {
            cfg.balloon_bias = b * 1024 * 1024;
        }

        cfg.vhost_user_blk = cmd.vhost_user_blk;
        cfg.vhost_user_console = cmd.vhost_user_console;
        cfg.vhost_user_gpu = cmd.vhost_user_gpu;
        cfg.vhost_user_mac80211_hwsim = cmd.vhost_user_mac80211_hwsim;
        cfg.vhost_user_net = cmd.vhost_user_net;
        cfg.vhost_user_rng = cmd.vhost_user_rng;
        cfg.vhost_user_vsock = cmd.vhost_user_vsock;
        cfg.vhost_user_wl = cmd.vhost_user_wl;

        #[cfg(feature = "direct")]
        {
            cfg.direct_pmio = cmd.direct_pmio;
            cfg.direct_mmio = cmd.direct_mmio;
            cfg.direct_level_irq = cmd.direct_level_irq;
            cfg.direct_edge_irq = cmd.direct_edge_irq;
            cfg.direct_gpe = cmd.direct_gpe;
            cfg.pcie_rp = cmd.pcie_rp;
            cfg.mmio_address_ranges = cmd.mmio_address_ranges.unwrap_or_default();
        }

        cfg.disable_virtio_intx = cmd.disable_virtio_intx;

        cfg.dmi_path = cmd.dmi_path;

        cfg.itmt = cmd.itmt;

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        if cmd.enable_pnp_data && cmd.force_calibrated_tsc_leaf {
            return Err(
                "Only one of [enable_pnp_data,force_calibrated_tsc_leaf] can be specified"
                    .to_string(),
            );
        }

        cfg.enable_pnp_data = cmd.enable_pnp_data;

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            cfg.force_calibrated_tsc_leaf = cmd.force_calibrated_tsc_leaf;
        }

        cfg.privileged_vm = cmd.privileged_vm;

        cfg.stub_pci_devices = cmd.stub_pci_devices;

        cfg.vvu_proxy = cmd.vvu_proxy;

        cfg.file_backed_mappings = cmd.file_backed_mappings;

        cfg.init_memory = cmd.init_memory;

        cfg.strict_balloon = cmd.strict_balloon;

        #[cfg(target_os = "android")]
        {
            cfg.task_profiles = cmd.task_profiles;
        }

        #[cfg(unix)]
        {
            cfg.vfio.extend(cmd.vfio);
            cfg.vfio.extend(cmd.vfio_platform);
        }

        // Now do validation of constructed config
        super::config::validate_config(&mut cfg)?;

        Ok(cfg)
    }
}
