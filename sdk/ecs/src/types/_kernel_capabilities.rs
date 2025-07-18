// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The Linux capabilities to add or remove from the default Docker configuration for a container defined in the task definition. For more detailed information about these Linux capabilities, see the <a href="http://man7.org/linux/man-pages/man7/capabilities.7.html">capabilities(7)</a> Linux manual page.</p>
/// <p>The following describes how Docker processes the Linux capabilities specified in the <code>add</code> and <code>drop</code> request parameters. For information about the latest behavior, see <a href="https://forums.docker.com/t/docker-compose-order-of-cap-drop-and-cap-add/97136/1">Docker Compose: order of cap_drop and cap_add</a> in the Docker Community Forum.</p>
/// <ul>
/// <li>
/// <p>When the container is a privleged container, the container capabilities are all of the default Docker capabilities. The capabilities specified in the <code>add</code> request parameter, and the <code>drop</code> request parameter are ignored.</p></li>
/// <li>
/// <p>When the <code>add</code> request parameter is set to ALL, the container capabilities are all of the default Docker capabilities, excluding those specified in the <code>drop</code> request parameter.</p></li>
/// <li>
/// <p>When the <code>drop</code> request parameter is set to ALL, the container capabilities are the capabilities specified in the <code>add</code> request parameter.</p></li>
/// <li>
/// <p>When the <code>add</code> request parameter and the <code>drop</code> request parameter are both empty, the capabilities the container capabilities are all of the default Docker capabilities.</p></li>
/// <li>
/// <p>The default is to first drop the capabilities specified in the <code>drop</code> request parameter, and then add the capabilities specified in the <code>add</code> request parameter.</p></li>
/// </ul>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct KernelCapabilities {
    /// <p>The Linux capabilities for the container that have been added to the default configuration provided by Docker. This parameter maps to <code>CapAdd</code> in the docker container create command and the <code>--cap-add</code> option to docker run.</p><note>
    /// <p>Tasks launched on Fargate only support adding the <code>SYS_PTRACE</code> kernel capability.</p>
    /// </note>
    /// <p>Valid values: <code>"ALL" | "AUDIT_CONTROL" | "AUDIT_WRITE" | "BLOCK_SUSPEND" | "CHOWN" | "DAC_OVERRIDE" | "DAC_READ_SEARCH" | "FOWNER" | "FSETID" | "IPC_LOCK" | "IPC_OWNER" | "KILL" | "LEASE" | "LINUX_IMMUTABLE" | "MAC_ADMIN" | "MAC_OVERRIDE" | "MKNOD" | "NET_ADMIN" | "NET_BIND_SERVICE" | "NET_BROADCAST" | "NET_RAW" | "SETFCAP" | "SETGID" | "SETPCAP" | "SETUID" | "SYS_ADMIN" | "SYS_BOOT" | "SYS_CHROOT" | "SYS_MODULE" | "SYS_NICE" | "SYS_PACCT" | "SYS_PTRACE" | "SYS_RAWIO" | "SYS_RESOURCE" | "SYS_TIME" | "SYS_TTY_CONFIG" | "SYSLOG" | "WAKE_ALARM"</code></p>
    pub add: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The Linux capabilities for the container that have been removed from the default configuration provided by Docker. This parameter maps to <code>CapDrop</code> in the docker container create command and the <code>--cap-drop</code> option to docker run.</p>
    /// <p>Valid values: <code>"ALL" | "AUDIT_CONTROL" | "AUDIT_WRITE" | "BLOCK_SUSPEND" | "CHOWN" | "DAC_OVERRIDE" | "DAC_READ_SEARCH" | "FOWNER" | "FSETID" | "IPC_LOCK" | "IPC_OWNER" | "KILL" | "LEASE" | "LINUX_IMMUTABLE" | "MAC_ADMIN" | "MAC_OVERRIDE" | "MKNOD" | "NET_ADMIN" | "NET_BIND_SERVICE" | "NET_BROADCAST" | "NET_RAW" | "SETFCAP" | "SETGID" | "SETPCAP" | "SETUID" | "SYS_ADMIN" | "SYS_BOOT" | "SYS_CHROOT" | "SYS_MODULE" | "SYS_NICE" | "SYS_PACCT" | "SYS_PTRACE" | "SYS_RAWIO" | "SYS_RESOURCE" | "SYS_TIME" | "SYS_TTY_CONFIG" | "SYSLOG" | "WAKE_ALARM"</code></p>
    pub drop: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl KernelCapabilities {
    /// <p>The Linux capabilities for the container that have been added to the default configuration provided by Docker. This parameter maps to <code>CapAdd</code> in the docker container create command and the <code>--cap-add</code> option to docker run.</p><note>
    /// <p>Tasks launched on Fargate only support adding the <code>SYS_PTRACE</code> kernel capability.</p>
    /// </note>
    /// <p>Valid values: <code>"ALL" | "AUDIT_CONTROL" | "AUDIT_WRITE" | "BLOCK_SUSPEND" | "CHOWN" | "DAC_OVERRIDE" | "DAC_READ_SEARCH" | "FOWNER" | "FSETID" | "IPC_LOCK" | "IPC_OWNER" | "KILL" | "LEASE" | "LINUX_IMMUTABLE" | "MAC_ADMIN" | "MAC_OVERRIDE" | "MKNOD" | "NET_ADMIN" | "NET_BIND_SERVICE" | "NET_BROADCAST" | "NET_RAW" | "SETFCAP" | "SETGID" | "SETPCAP" | "SETUID" | "SYS_ADMIN" | "SYS_BOOT" | "SYS_CHROOT" | "SYS_MODULE" | "SYS_NICE" | "SYS_PACCT" | "SYS_PTRACE" | "SYS_RAWIO" | "SYS_RESOURCE" | "SYS_TIME" | "SYS_TTY_CONFIG" | "SYSLOG" | "WAKE_ALARM"</code></p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.add.is_none()`.
    pub fn add(&self) -> &[::std::string::String] {
        self.add.as_deref().unwrap_or_default()
    }
    /// <p>The Linux capabilities for the container that have been removed from the default configuration provided by Docker. This parameter maps to <code>CapDrop</code> in the docker container create command and the <code>--cap-drop</code> option to docker run.</p>
    /// <p>Valid values: <code>"ALL" | "AUDIT_CONTROL" | "AUDIT_WRITE" | "BLOCK_SUSPEND" | "CHOWN" | "DAC_OVERRIDE" | "DAC_READ_SEARCH" | "FOWNER" | "FSETID" | "IPC_LOCK" | "IPC_OWNER" | "KILL" | "LEASE" | "LINUX_IMMUTABLE" | "MAC_ADMIN" | "MAC_OVERRIDE" | "MKNOD" | "NET_ADMIN" | "NET_BIND_SERVICE" | "NET_BROADCAST" | "NET_RAW" | "SETFCAP" | "SETGID" | "SETPCAP" | "SETUID" | "SYS_ADMIN" | "SYS_BOOT" | "SYS_CHROOT" | "SYS_MODULE" | "SYS_NICE" | "SYS_PACCT" | "SYS_PTRACE" | "SYS_RAWIO" | "SYS_RESOURCE" | "SYS_TIME" | "SYS_TTY_CONFIG" | "SYSLOG" | "WAKE_ALARM"</code></p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.drop.is_none()`.
    pub fn drop(&self) -> &[::std::string::String] {
        self.drop.as_deref().unwrap_or_default()
    }
}
impl KernelCapabilities {
    /// Creates a new builder-style object to manufacture [`KernelCapabilities`](crate::types::KernelCapabilities).
    pub fn builder() -> crate::types::builders::KernelCapabilitiesBuilder {
        crate::types::builders::KernelCapabilitiesBuilder::default()
    }
}

/// A builder for [`KernelCapabilities`](crate::types::KernelCapabilities).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct KernelCapabilitiesBuilder {
    pub(crate) add: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) drop: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl KernelCapabilitiesBuilder {
    /// Appends an item to `add`.
    ///
    /// To override the contents of this collection use [`set_add`](Self::set_add).
    ///
    /// <p>The Linux capabilities for the container that have been added to the default configuration provided by Docker. This parameter maps to <code>CapAdd</code> in the docker container create command and the <code>--cap-add</code> option to docker run.</p><note>
    /// <p>Tasks launched on Fargate only support adding the <code>SYS_PTRACE</code> kernel capability.</p>
    /// </note>
    /// <p>Valid values: <code>"ALL" | "AUDIT_CONTROL" | "AUDIT_WRITE" | "BLOCK_SUSPEND" | "CHOWN" | "DAC_OVERRIDE" | "DAC_READ_SEARCH" | "FOWNER" | "FSETID" | "IPC_LOCK" | "IPC_OWNER" | "KILL" | "LEASE" | "LINUX_IMMUTABLE" | "MAC_ADMIN" | "MAC_OVERRIDE" | "MKNOD" | "NET_ADMIN" | "NET_BIND_SERVICE" | "NET_BROADCAST" | "NET_RAW" | "SETFCAP" | "SETGID" | "SETPCAP" | "SETUID" | "SYS_ADMIN" | "SYS_BOOT" | "SYS_CHROOT" | "SYS_MODULE" | "SYS_NICE" | "SYS_PACCT" | "SYS_PTRACE" | "SYS_RAWIO" | "SYS_RESOURCE" | "SYS_TIME" | "SYS_TTY_CONFIG" | "SYSLOG" | "WAKE_ALARM"</code></p>
    pub fn add(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.add.unwrap_or_default();
        v.push(input.into());
        self.add = ::std::option::Option::Some(v);
        self
    }
    /// <p>The Linux capabilities for the container that have been added to the default configuration provided by Docker. This parameter maps to <code>CapAdd</code> in the docker container create command and the <code>--cap-add</code> option to docker run.</p><note>
    /// <p>Tasks launched on Fargate only support adding the <code>SYS_PTRACE</code> kernel capability.</p>
    /// </note>
    /// <p>Valid values: <code>"ALL" | "AUDIT_CONTROL" | "AUDIT_WRITE" | "BLOCK_SUSPEND" | "CHOWN" | "DAC_OVERRIDE" | "DAC_READ_SEARCH" | "FOWNER" | "FSETID" | "IPC_LOCK" | "IPC_OWNER" | "KILL" | "LEASE" | "LINUX_IMMUTABLE" | "MAC_ADMIN" | "MAC_OVERRIDE" | "MKNOD" | "NET_ADMIN" | "NET_BIND_SERVICE" | "NET_BROADCAST" | "NET_RAW" | "SETFCAP" | "SETGID" | "SETPCAP" | "SETUID" | "SYS_ADMIN" | "SYS_BOOT" | "SYS_CHROOT" | "SYS_MODULE" | "SYS_NICE" | "SYS_PACCT" | "SYS_PTRACE" | "SYS_RAWIO" | "SYS_RESOURCE" | "SYS_TIME" | "SYS_TTY_CONFIG" | "SYSLOG" | "WAKE_ALARM"</code></p>
    pub fn set_add(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.add = input;
        self
    }
    /// <p>The Linux capabilities for the container that have been added to the default configuration provided by Docker. This parameter maps to <code>CapAdd</code> in the docker container create command and the <code>--cap-add</code> option to docker run.</p><note>
    /// <p>Tasks launched on Fargate only support adding the <code>SYS_PTRACE</code> kernel capability.</p>
    /// </note>
    /// <p>Valid values: <code>"ALL" | "AUDIT_CONTROL" | "AUDIT_WRITE" | "BLOCK_SUSPEND" | "CHOWN" | "DAC_OVERRIDE" | "DAC_READ_SEARCH" | "FOWNER" | "FSETID" | "IPC_LOCK" | "IPC_OWNER" | "KILL" | "LEASE" | "LINUX_IMMUTABLE" | "MAC_ADMIN" | "MAC_OVERRIDE" | "MKNOD" | "NET_ADMIN" | "NET_BIND_SERVICE" | "NET_BROADCAST" | "NET_RAW" | "SETFCAP" | "SETGID" | "SETPCAP" | "SETUID" | "SYS_ADMIN" | "SYS_BOOT" | "SYS_CHROOT" | "SYS_MODULE" | "SYS_NICE" | "SYS_PACCT" | "SYS_PTRACE" | "SYS_RAWIO" | "SYS_RESOURCE" | "SYS_TIME" | "SYS_TTY_CONFIG" | "SYSLOG" | "WAKE_ALARM"</code></p>
    pub fn get_add(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.add
    }
    /// Appends an item to `drop`.
    ///
    /// To override the contents of this collection use [`set_drop`](Self::set_drop).
    ///
    /// <p>The Linux capabilities for the container that have been removed from the default configuration provided by Docker. This parameter maps to <code>CapDrop</code> in the docker container create command and the <code>--cap-drop</code> option to docker run.</p>
    /// <p>Valid values: <code>"ALL" | "AUDIT_CONTROL" | "AUDIT_WRITE" | "BLOCK_SUSPEND" | "CHOWN" | "DAC_OVERRIDE" | "DAC_READ_SEARCH" | "FOWNER" | "FSETID" | "IPC_LOCK" | "IPC_OWNER" | "KILL" | "LEASE" | "LINUX_IMMUTABLE" | "MAC_ADMIN" | "MAC_OVERRIDE" | "MKNOD" | "NET_ADMIN" | "NET_BIND_SERVICE" | "NET_BROADCAST" | "NET_RAW" | "SETFCAP" | "SETGID" | "SETPCAP" | "SETUID" | "SYS_ADMIN" | "SYS_BOOT" | "SYS_CHROOT" | "SYS_MODULE" | "SYS_NICE" | "SYS_PACCT" | "SYS_PTRACE" | "SYS_RAWIO" | "SYS_RESOURCE" | "SYS_TIME" | "SYS_TTY_CONFIG" | "SYSLOG" | "WAKE_ALARM"</code></p>
    pub fn drop(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.drop.unwrap_or_default();
        v.push(input.into());
        self.drop = ::std::option::Option::Some(v);
        self
    }
    /// <p>The Linux capabilities for the container that have been removed from the default configuration provided by Docker. This parameter maps to <code>CapDrop</code> in the docker container create command and the <code>--cap-drop</code> option to docker run.</p>
    /// <p>Valid values: <code>"ALL" | "AUDIT_CONTROL" | "AUDIT_WRITE" | "BLOCK_SUSPEND" | "CHOWN" | "DAC_OVERRIDE" | "DAC_READ_SEARCH" | "FOWNER" | "FSETID" | "IPC_LOCK" | "IPC_OWNER" | "KILL" | "LEASE" | "LINUX_IMMUTABLE" | "MAC_ADMIN" | "MAC_OVERRIDE" | "MKNOD" | "NET_ADMIN" | "NET_BIND_SERVICE" | "NET_BROADCAST" | "NET_RAW" | "SETFCAP" | "SETGID" | "SETPCAP" | "SETUID" | "SYS_ADMIN" | "SYS_BOOT" | "SYS_CHROOT" | "SYS_MODULE" | "SYS_NICE" | "SYS_PACCT" | "SYS_PTRACE" | "SYS_RAWIO" | "SYS_RESOURCE" | "SYS_TIME" | "SYS_TTY_CONFIG" | "SYSLOG" | "WAKE_ALARM"</code></p>
    pub fn set_drop(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.drop = input;
        self
    }
    /// <p>The Linux capabilities for the container that have been removed from the default configuration provided by Docker. This parameter maps to <code>CapDrop</code> in the docker container create command and the <code>--cap-drop</code> option to docker run.</p>
    /// <p>Valid values: <code>"ALL" | "AUDIT_CONTROL" | "AUDIT_WRITE" | "BLOCK_SUSPEND" | "CHOWN" | "DAC_OVERRIDE" | "DAC_READ_SEARCH" | "FOWNER" | "FSETID" | "IPC_LOCK" | "IPC_OWNER" | "KILL" | "LEASE" | "LINUX_IMMUTABLE" | "MAC_ADMIN" | "MAC_OVERRIDE" | "MKNOD" | "NET_ADMIN" | "NET_BIND_SERVICE" | "NET_BROADCAST" | "NET_RAW" | "SETFCAP" | "SETGID" | "SETPCAP" | "SETUID" | "SYS_ADMIN" | "SYS_BOOT" | "SYS_CHROOT" | "SYS_MODULE" | "SYS_NICE" | "SYS_PACCT" | "SYS_PTRACE" | "SYS_RAWIO" | "SYS_RESOURCE" | "SYS_TIME" | "SYS_TTY_CONFIG" | "SYSLOG" | "WAKE_ALARM"</code></p>
    pub fn get_drop(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.drop
    }
    /// Consumes the builder and constructs a [`KernelCapabilities`](crate::types::KernelCapabilities).
    pub fn build(self) -> crate::types::KernelCapabilities {
        crate::types::KernelCapabilities {
            add: self.add,
            drop: self.drop,
        }
    }
}
