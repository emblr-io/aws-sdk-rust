// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Additional information about the suspicious activity.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RuntimeContext {
    /// <p>Information about the process that modified the current process. This is available for multiple finding types.</p>
    pub modifying_process: ::std::option::Option<crate::types::ProcessDetails>,
    /// <p>The timestamp at which the process modified the current process. The timestamp is in UTC date string format.</p>
    pub modified_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The path to the script that was executed.</p>
    pub script_path: ::std::option::Option<::std::string::String>,
    /// <p>The path to the new library that was loaded.</p>
    pub library_path: ::std::option::Option<::std::string::String>,
    /// <p>The value of the LD_PRELOAD environment variable.</p>
    pub ld_preload_value: ::std::option::Option<::std::string::String>,
    /// <p>The path to the docket socket that was accessed.</p>
    pub socket_path: ::std::option::Option<::std::string::String>,
    /// <p>The path to the leveraged <code>runc</code> implementation.</p>
    pub runc_binary_path: ::std::option::Option<::std::string::String>,
    /// <p>The path in the container that modified the release agent file.</p>
    pub release_agent_path: ::std::option::Option<::std::string::String>,
    /// <p>The path on the host that is mounted by the container.</p>
    pub mount_source: ::std::option::Option<::std::string::String>,
    /// <p>The path in the container that is mapped to the host directory.</p>
    pub mount_target: ::std::option::Option<::std::string::String>,
    /// <p>Represents the type of mounted fileSystem.</p>
    pub file_system_type: ::std::option::Option<::std::string::String>,
    /// <p>Represents options that control the behavior of a runtime operation or action. For example, a filesystem mount operation may contain a read-only flag.</p>
    pub flags: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The name of the module loaded into the kernel.</p>
    pub module_name: ::std::option::Option<::std::string::String>,
    /// <p>The path to the module loaded into the kernel.</p>
    pub module_file_path: ::std::option::Option<::std::string::String>,
    /// <p>The <code>SHA256</code> hash of the module.</p>
    pub module_sha256: ::std::option::Option<::std::string::String>,
    /// <p>The path to the modified shell history file.</p>
    pub shell_history_file_path: ::std::option::Option<::std::string::String>,
    /// <p>Information about the process that had its memory overwritten by the current process.</p>
    pub target_process: ::std::option::Option<crate::types::ProcessDetails>,
    /// <p>Represents the communication protocol associated with the address. For example, the address family <code>AF_INET</code> is used for IP version of 4 protocol.</p>
    pub address_family: ::std::option::Option<::std::string::String>,
    /// <p>Specifies a particular protocol within the address family. Usually there is a single protocol in address families. For example, the address family <code>AF_INET</code> only has the IP protocol.</p>
    pub iana_protocol_number: ::std::option::Option<i32>,
    /// <p>Specifies the Region of a process's address space such as stack and heap.</p>
    pub memory_regions: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Name of the potentially suspicious tool.</p>
    pub tool_name: ::std::option::Option<::std::string::String>,
    /// <p>Category that the tool belongs to. Some of the examples are Backdoor Tool, Pentest Tool, Network Scanner, and Network Sniffer.</p>
    pub tool_category: ::std::option::Option<::std::string::String>,
    /// <p>Name of the security service that has been potentially disabled.</p>
    pub service_name: ::std::option::Option<::std::string::String>,
    /// <p>Example of the command line involved in the suspicious activity.</p>
    pub command_line_example: ::std::option::Option<::std::string::String>,
    /// <p>The suspicious file path for which the threat intelligence details were found.</p>
    pub threat_file_path: ::std::option::Option<::std::string::String>,
}
impl RuntimeContext {
    /// <p>Information about the process that modified the current process. This is available for multiple finding types.</p>
    pub fn modifying_process(&self) -> ::std::option::Option<&crate::types::ProcessDetails> {
        self.modifying_process.as_ref()
    }
    /// <p>The timestamp at which the process modified the current process. The timestamp is in UTC date string format.</p>
    pub fn modified_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.modified_at.as_ref()
    }
    /// <p>The path to the script that was executed.</p>
    pub fn script_path(&self) -> ::std::option::Option<&str> {
        self.script_path.as_deref()
    }
    /// <p>The path to the new library that was loaded.</p>
    pub fn library_path(&self) -> ::std::option::Option<&str> {
        self.library_path.as_deref()
    }
    /// <p>The value of the LD_PRELOAD environment variable.</p>
    pub fn ld_preload_value(&self) -> ::std::option::Option<&str> {
        self.ld_preload_value.as_deref()
    }
    /// <p>The path to the docket socket that was accessed.</p>
    pub fn socket_path(&self) -> ::std::option::Option<&str> {
        self.socket_path.as_deref()
    }
    /// <p>The path to the leveraged <code>runc</code> implementation.</p>
    pub fn runc_binary_path(&self) -> ::std::option::Option<&str> {
        self.runc_binary_path.as_deref()
    }
    /// <p>The path in the container that modified the release agent file.</p>
    pub fn release_agent_path(&self) -> ::std::option::Option<&str> {
        self.release_agent_path.as_deref()
    }
    /// <p>The path on the host that is mounted by the container.</p>
    pub fn mount_source(&self) -> ::std::option::Option<&str> {
        self.mount_source.as_deref()
    }
    /// <p>The path in the container that is mapped to the host directory.</p>
    pub fn mount_target(&self) -> ::std::option::Option<&str> {
        self.mount_target.as_deref()
    }
    /// <p>Represents the type of mounted fileSystem.</p>
    pub fn file_system_type(&self) -> ::std::option::Option<&str> {
        self.file_system_type.as_deref()
    }
    /// <p>Represents options that control the behavior of a runtime operation or action. For example, a filesystem mount operation may contain a read-only flag.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.flags.is_none()`.
    pub fn flags(&self) -> &[::std::string::String] {
        self.flags.as_deref().unwrap_or_default()
    }
    /// <p>The name of the module loaded into the kernel.</p>
    pub fn module_name(&self) -> ::std::option::Option<&str> {
        self.module_name.as_deref()
    }
    /// <p>The path to the module loaded into the kernel.</p>
    pub fn module_file_path(&self) -> ::std::option::Option<&str> {
        self.module_file_path.as_deref()
    }
    /// <p>The <code>SHA256</code> hash of the module.</p>
    pub fn module_sha256(&self) -> ::std::option::Option<&str> {
        self.module_sha256.as_deref()
    }
    /// <p>The path to the modified shell history file.</p>
    pub fn shell_history_file_path(&self) -> ::std::option::Option<&str> {
        self.shell_history_file_path.as_deref()
    }
    /// <p>Information about the process that had its memory overwritten by the current process.</p>
    pub fn target_process(&self) -> ::std::option::Option<&crate::types::ProcessDetails> {
        self.target_process.as_ref()
    }
    /// <p>Represents the communication protocol associated with the address. For example, the address family <code>AF_INET</code> is used for IP version of 4 protocol.</p>
    pub fn address_family(&self) -> ::std::option::Option<&str> {
        self.address_family.as_deref()
    }
    /// <p>Specifies a particular protocol within the address family. Usually there is a single protocol in address families. For example, the address family <code>AF_INET</code> only has the IP protocol.</p>
    pub fn iana_protocol_number(&self) -> ::std::option::Option<i32> {
        self.iana_protocol_number
    }
    /// <p>Specifies the Region of a process's address space such as stack and heap.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.memory_regions.is_none()`.
    pub fn memory_regions(&self) -> &[::std::string::String] {
        self.memory_regions.as_deref().unwrap_or_default()
    }
    /// <p>Name of the potentially suspicious tool.</p>
    pub fn tool_name(&self) -> ::std::option::Option<&str> {
        self.tool_name.as_deref()
    }
    /// <p>Category that the tool belongs to. Some of the examples are Backdoor Tool, Pentest Tool, Network Scanner, and Network Sniffer.</p>
    pub fn tool_category(&self) -> ::std::option::Option<&str> {
        self.tool_category.as_deref()
    }
    /// <p>Name of the security service that has been potentially disabled.</p>
    pub fn service_name(&self) -> ::std::option::Option<&str> {
        self.service_name.as_deref()
    }
    /// <p>Example of the command line involved in the suspicious activity.</p>
    pub fn command_line_example(&self) -> ::std::option::Option<&str> {
        self.command_line_example.as_deref()
    }
    /// <p>The suspicious file path for which the threat intelligence details were found.</p>
    pub fn threat_file_path(&self) -> ::std::option::Option<&str> {
        self.threat_file_path.as_deref()
    }
}
impl RuntimeContext {
    /// Creates a new builder-style object to manufacture [`RuntimeContext`](crate::types::RuntimeContext).
    pub fn builder() -> crate::types::builders::RuntimeContextBuilder {
        crate::types::builders::RuntimeContextBuilder::default()
    }
}

/// A builder for [`RuntimeContext`](crate::types::RuntimeContext).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RuntimeContextBuilder {
    pub(crate) modifying_process: ::std::option::Option<crate::types::ProcessDetails>,
    pub(crate) modified_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) script_path: ::std::option::Option<::std::string::String>,
    pub(crate) library_path: ::std::option::Option<::std::string::String>,
    pub(crate) ld_preload_value: ::std::option::Option<::std::string::String>,
    pub(crate) socket_path: ::std::option::Option<::std::string::String>,
    pub(crate) runc_binary_path: ::std::option::Option<::std::string::String>,
    pub(crate) release_agent_path: ::std::option::Option<::std::string::String>,
    pub(crate) mount_source: ::std::option::Option<::std::string::String>,
    pub(crate) mount_target: ::std::option::Option<::std::string::String>,
    pub(crate) file_system_type: ::std::option::Option<::std::string::String>,
    pub(crate) flags: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) module_name: ::std::option::Option<::std::string::String>,
    pub(crate) module_file_path: ::std::option::Option<::std::string::String>,
    pub(crate) module_sha256: ::std::option::Option<::std::string::String>,
    pub(crate) shell_history_file_path: ::std::option::Option<::std::string::String>,
    pub(crate) target_process: ::std::option::Option<crate::types::ProcessDetails>,
    pub(crate) address_family: ::std::option::Option<::std::string::String>,
    pub(crate) iana_protocol_number: ::std::option::Option<i32>,
    pub(crate) memory_regions: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) tool_name: ::std::option::Option<::std::string::String>,
    pub(crate) tool_category: ::std::option::Option<::std::string::String>,
    pub(crate) service_name: ::std::option::Option<::std::string::String>,
    pub(crate) command_line_example: ::std::option::Option<::std::string::String>,
    pub(crate) threat_file_path: ::std::option::Option<::std::string::String>,
}
impl RuntimeContextBuilder {
    /// <p>Information about the process that modified the current process. This is available for multiple finding types.</p>
    pub fn modifying_process(mut self, input: crate::types::ProcessDetails) -> Self {
        self.modifying_process = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the process that modified the current process. This is available for multiple finding types.</p>
    pub fn set_modifying_process(mut self, input: ::std::option::Option<crate::types::ProcessDetails>) -> Self {
        self.modifying_process = input;
        self
    }
    /// <p>Information about the process that modified the current process. This is available for multiple finding types.</p>
    pub fn get_modifying_process(&self) -> &::std::option::Option<crate::types::ProcessDetails> {
        &self.modifying_process
    }
    /// <p>The timestamp at which the process modified the current process. The timestamp is in UTC date string format.</p>
    pub fn modified_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.modified_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp at which the process modified the current process. The timestamp is in UTC date string format.</p>
    pub fn set_modified_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.modified_at = input;
        self
    }
    /// <p>The timestamp at which the process modified the current process. The timestamp is in UTC date string format.</p>
    pub fn get_modified_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.modified_at
    }
    /// <p>The path to the script that was executed.</p>
    pub fn script_path(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.script_path = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The path to the script that was executed.</p>
    pub fn set_script_path(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.script_path = input;
        self
    }
    /// <p>The path to the script that was executed.</p>
    pub fn get_script_path(&self) -> &::std::option::Option<::std::string::String> {
        &self.script_path
    }
    /// <p>The path to the new library that was loaded.</p>
    pub fn library_path(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.library_path = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The path to the new library that was loaded.</p>
    pub fn set_library_path(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.library_path = input;
        self
    }
    /// <p>The path to the new library that was loaded.</p>
    pub fn get_library_path(&self) -> &::std::option::Option<::std::string::String> {
        &self.library_path
    }
    /// <p>The value of the LD_PRELOAD environment variable.</p>
    pub fn ld_preload_value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ld_preload_value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value of the LD_PRELOAD environment variable.</p>
    pub fn set_ld_preload_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ld_preload_value = input;
        self
    }
    /// <p>The value of the LD_PRELOAD environment variable.</p>
    pub fn get_ld_preload_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.ld_preload_value
    }
    /// <p>The path to the docket socket that was accessed.</p>
    pub fn socket_path(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.socket_path = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The path to the docket socket that was accessed.</p>
    pub fn set_socket_path(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.socket_path = input;
        self
    }
    /// <p>The path to the docket socket that was accessed.</p>
    pub fn get_socket_path(&self) -> &::std::option::Option<::std::string::String> {
        &self.socket_path
    }
    /// <p>The path to the leveraged <code>runc</code> implementation.</p>
    pub fn runc_binary_path(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.runc_binary_path = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The path to the leveraged <code>runc</code> implementation.</p>
    pub fn set_runc_binary_path(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.runc_binary_path = input;
        self
    }
    /// <p>The path to the leveraged <code>runc</code> implementation.</p>
    pub fn get_runc_binary_path(&self) -> &::std::option::Option<::std::string::String> {
        &self.runc_binary_path
    }
    /// <p>The path in the container that modified the release agent file.</p>
    pub fn release_agent_path(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.release_agent_path = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The path in the container that modified the release agent file.</p>
    pub fn set_release_agent_path(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.release_agent_path = input;
        self
    }
    /// <p>The path in the container that modified the release agent file.</p>
    pub fn get_release_agent_path(&self) -> &::std::option::Option<::std::string::String> {
        &self.release_agent_path
    }
    /// <p>The path on the host that is mounted by the container.</p>
    pub fn mount_source(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.mount_source = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The path on the host that is mounted by the container.</p>
    pub fn set_mount_source(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.mount_source = input;
        self
    }
    /// <p>The path on the host that is mounted by the container.</p>
    pub fn get_mount_source(&self) -> &::std::option::Option<::std::string::String> {
        &self.mount_source
    }
    /// <p>The path in the container that is mapped to the host directory.</p>
    pub fn mount_target(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.mount_target = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The path in the container that is mapped to the host directory.</p>
    pub fn set_mount_target(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.mount_target = input;
        self
    }
    /// <p>The path in the container that is mapped to the host directory.</p>
    pub fn get_mount_target(&self) -> &::std::option::Option<::std::string::String> {
        &self.mount_target
    }
    /// <p>Represents the type of mounted fileSystem.</p>
    pub fn file_system_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.file_system_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Represents the type of mounted fileSystem.</p>
    pub fn set_file_system_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.file_system_type = input;
        self
    }
    /// <p>Represents the type of mounted fileSystem.</p>
    pub fn get_file_system_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.file_system_type
    }
    /// Appends an item to `flags`.
    ///
    /// To override the contents of this collection use [`set_flags`](Self::set_flags).
    ///
    /// <p>Represents options that control the behavior of a runtime operation or action. For example, a filesystem mount operation may contain a read-only flag.</p>
    pub fn flags(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.flags.unwrap_or_default();
        v.push(input.into());
        self.flags = ::std::option::Option::Some(v);
        self
    }
    /// <p>Represents options that control the behavior of a runtime operation or action. For example, a filesystem mount operation may contain a read-only flag.</p>
    pub fn set_flags(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.flags = input;
        self
    }
    /// <p>Represents options that control the behavior of a runtime operation or action. For example, a filesystem mount operation may contain a read-only flag.</p>
    pub fn get_flags(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.flags
    }
    /// <p>The name of the module loaded into the kernel.</p>
    pub fn module_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.module_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the module loaded into the kernel.</p>
    pub fn set_module_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.module_name = input;
        self
    }
    /// <p>The name of the module loaded into the kernel.</p>
    pub fn get_module_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.module_name
    }
    /// <p>The path to the module loaded into the kernel.</p>
    pub fn module_file_path(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.module_file_path = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The path to the module loaded into the kernel.</p>
    pub fn set_module_file_path(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.module_file_path = input;
        self
    }
    /// <p>The path to the module loaded into the kernel.</p>
    pub fn get_module_file_path(&self) -> &::std::option::Option<::std::string::String> {
        &self.module_file_path
    }
    /// <p>The <code>SHA256</code> hash of the module.</p>
    pub fn module_sha256(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.module_sha256 = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>SHA256</code> hash of the module.</p>
    pub fn set_module_sha256(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.module_sha256 = input;
        self
    }
    /// <p>The <code>SHA256</code> hash of the module.</p>
    pub fn get_module_sha256(&self) -> &::std::option::Option<::std::string::String> {
        &self.module_sha256
    }
    /// <p>The path to the modified shell history file.</p>
    pub fn shell_history_file_path(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.shell_history_file_path = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The path to the modified shell history file.</p>
    pub fn set_shell_history_file_path(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.shell_history_file_path = input;
        self
    }
    /// <p>The path to the modified shell history file.</p>
    pub fn get_shell_history_file_path(&self) -> &::std::option::Option<::std::string::String> {
        &self.shell_history_file_path
    }
    /// <p>Information about the process that had its memory overwritten by the current process.</p>
    pub fn target_process(mut self, input: crate::types::ProcessDetails) -> Self {
        self.target_process = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the process that had its memory overwritten by the current process.</p>
    pub fn set_target_process(mut self, input: ::std::option::Option<crate::types::ProcessDetails>) -> Self {
        self.target_process = input;
        self
    }
    /// <p>Information about the process that had its memory overwritten by the current process.</p>
    pub fn get_target_process(&self) -> &::std::option::Option<crate::types::ProcessDetails> {
        &self.target_process
    }
    /// <p>Represents the communication protocol associated with the address. For example, the address family <code>AF_INET</code> is used for IP version of 4 protocol.</p>
    pub fn address_family(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.address_family = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Represents the communication protocol associated with the address. For example, the address family <code>AF_INET</code> is used for IP version of 4 protocol.</p>
    pub fn set_address_family(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.address_family = input;
        self
    }
    /// <p>Represents the communication protocol associated with the address. For example, the address family <code>AF_INET</code> is used for IP version of 4 protocol.</p>
    pub fn get_address_family(&self) -> &::std::option::Option<::std::string::String> {
        &self.address_family
    }
    /// <p>Specifies a particular protocol within the address family. Usually there is a single protocol in address families. For example, the address family <code>AF_INET</code> only has the IP protocol.</p>
    pub fn iana_protocol_number(mut self, input: i32) -> Self {
        self.iana_protocol_number = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies a particular protocol within the address family. Usually there is a single protocol in address families. For example, the address family <code>AF_INET</code> only has the IP protocol.</p>
    pub fn set_iana_protocol_number(mut self, input: ::std::option::Option<i32>) -> Self {
        self.iana_protocol_number = input;
        self
    }
    /// <p>Specifies a particular protocol within the address family. Usually there is a single protocol in address families. For example, the address family <code>AF_INET</code> only has the IP protocol.</p>
    pub fn get_iana_protocol_number(&self) -> &::std::option::Option<i32> {
        &self.iana_protocol_number
    }
    /// Appends an item to `memory_regions`.
    ///
    /// To override the contents of this collection use [`set_memory_regions`](Self::set_memory_regions).
    ///
    /// <p>Specifies the Region of a process's address space such as stack and heap.</p>
    pub fn memory_regions(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.memory_regions.unwrap_or_default();
        v.push(input.into());
        self.memory_regions = ::std::option::Option::Some(v);
        self
    }
    /// <p>Specifies the Region of a process's address space such as stack and heap.</p>
    pub fn set_memory_regions(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.memory_regions = input;
        self
    }
    /// <p>Specifies the Region of a process's address space such as stack and heap.</p>
    pub fn get_memory_regions(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.memory_regions
    }
    /// <p>Name of the potentially suspicious tool.</p>
    pub fn tool_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.tool_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of the potentially suspicious tool.</p>
    pub fn set_tool_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.tool_name = input;
        self
    }
    /// <p>Name of the potentially suspicious tool.</p>
    pub fn get_tool_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.tool_name
    }
    /// <p>Category that the tool belongs to. Some of the examples are Backdoor Tool, Pentest Tool, Network Scanner, and Network Sniffer.</p>
    pub fn tool_category(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.tool_category = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Category that the tool belongs to. Some of the examples are Backdoor Tool, Pentest Tool, Network Scanner, and Network Sniffer.</p>
    pub fn set_tool_category(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.tool_category = input;
        self
    }
    /// <p>Category that the tool belongs to. Some of the examples are Backdoor Tool, Pentest Tool, Network Scanner, and Network Sniffer.</p>
    pub fn get_tool_category(&self) -> &::std::option::Option<::std::string::String> {
        &self.tool_category
    }
    /// <p>Name of the security service that has been potentially disabled.</p>
    pub fn service_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of the security service that has been potentially disabled.</p>
    pub fn set_service_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_name = input;
        self
    }
    /// <p>Name of the security service that has been potentially disabled.</p>
    pub fn get_service_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_name
    }
    /// <p>Example of the command line involved in the suspicious activity.</p>
    pub fn command_line_example(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.command_line_example = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Example of the command line involved in the suspicious activity.</p>
    pub fn set_command_line_example(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.command_line_example = input;
        self
    }
    /// <p>Example of the command line involved in the suspicious activity.</p>
    pub fn get_command_line_example(&self) -> &::std::option::Option<::std::string::String> {
        &self.command_line_example
    }
    /// <p>The suspicious file path for which the threat intelligence details were found.</p>
    pub fn threat_file_path(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.threat_file_path = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The suspicious file path for which the threat intelligence details were found.</p>
    pub fn set_threat_file_path(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.threat_file_path = input;
        self
    }
    /// <p>The suspicious file path for which the threat intelligence details were found.</p>
    pub fn get_threat_file_path(&self) -> &::std::option::Option<::std::string::String> {
        &self.threat_file_path
    }
    /// Consumes the builder and constructs a [`RuntimeContext`](crate::types::RuntimeContext).
    pub fn build(self) -> crate::types::RuntimeContext {
        crate::types::RuntimeContext {
            modifying_process: self.modifying_process,
            modified_at: self.modified_at,
            script_path: self.script_path,
            library_path: self.library_path,
            ld_preload_value: self.ld_preload_value,
            socket_path: self.socket_path,
            runc_binary_path: self.runc_binary_path,
            release_agent_path: self.release_agent_path,
            mount_source: self.mount_source,
            mount_target: self.mount_target,
            file_system_type: self.file_system_type,
            flags: self.flags,
            module_name: self.module_name,
            module_file_path: self.module_file_path,
            module_sha256: self.module_sha256,
            shell_history_file_path: self.shell_history_file_path,
            target_process: self.target_process,
            address_family: self.address_family,
            iana_protocol_number: self.iana_protocol_number,
            memory_regions: self.memory_regions,
            tool_name: self.tool_name,
            tool_category: self.tool_category,
            service_name: self.service_name,
            command_line_example: self.command_line_example,
            threat_file_path: self.threat_file_path,
        }
    }
}
