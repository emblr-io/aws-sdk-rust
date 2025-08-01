// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the properties of a Dedicated Host.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct HostProperties {
    /// <p>The number of cores on the Dedicated Host.</p>
    pub cores: ::std::option::Option<i32>,
    /// <p>The instance type supported by the Dedicated Host. For example, <code>m5.large</code>. If the host supports multiple instance types, no <b>instanceType</b> is returned.</p>
    pub instance_type: ::std::option::Option<::std::string::String>,
    /// <p>The instance family supported by the Dedicated Host. For example, <code>m5</code>.</p>
    pub instance_family: ::std::option::Option<::std::string::String>,
    /// <p>The number of sockets on the Dedicated Host.</p>
    pub sockets: ::std::option::Option<i32>,
    /// <p>The total number of vCPUs on the Dedicated Host.</p>
    pub total_v_cpus: ::std::option::Option<i32>,
}
impl HostProperties {
    /// <p>The number of cores on the Dedicated Host.</p>
    pub fn cores(&self) -> ::std::option::Option<i32> {
        self.cores
    }
    /// <p>The instance type supported by the Dedicated Host. For example, <code>m5.large</code>. If the host supports multiple instance types, no <b>instanceType</b> is returned.</p>
    pub fn instance_type(&self) -> ::std::option::Option<&str> {
        self.instance_type.as_deref()
    }
    /// <p>The instance family supported by the Dedicated Host. For example, <code>m5</code>.</p>
    pub fn instance_family(&self) -> ::std::option::Option<&str> {
        self.instance_family.as_deref()
    }
    /// <p>The number of sockets on the Dedicated Host.</p>
    pub fn sockets(&self) -> ::std::option::Option<i32> {
        self.sockets
    }
    /// <p>The total number of vCPUs on the Dedicated Host.</p>
    pub fn total_v_cpus(&self) -> ::std::option::Option<i32> {
        self.total_v_cpus
    }
}
impl HostProperties {
    /// Creates a new builder-style object to manufacture [`HostProperties`](crate::types::HostProperties).
    pub fn builder() -> crate::types::builders::HostPropertiesBuilder {
        crate::types::builders::HostPropertiesBuilder::default()
    }
}

/// A builder for [`HostProperties`](crate::types::HostProperties).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct HostPropertiesBuilder {
    pub(crate) cores: ::std::option::Option<i32>,
    pub(crate) instance_type: ::std::option::Option<::std::string::String>,
    pub(crate) instance_family: ::std::option::Option<::std::string::String>,
    pub(crate) sockets: ::std::option::Option<i32>,
    pub(crate) total_v_cpus: ::std::option::Option<i32>,
}
impl HostPropertiesBuilder {
    /// <p>The number of cores on the Dedicated Host.</p>
    pub fn cores(mut self, input: i32) -> Self {
        self.cores = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of cores on the Dedicated Host.</p>
    pub fn set_cores(mut self, input: ::std::option::Option<i32>) -> Self {
        self.cores = input;
        self
    }
    /// <p>The number of cores on the Dedicated Host.</p>
    pub fn get_cores(&self) -> &::std::option::Option<i32> {
        &self.cores
    }
    /// <p>The instance type supported by the Dedicated Host. For example, <code>m5.large</code>. If the host supports multiple instance types, no <b>instanceType</b> is returned.</p>
    pub fn instance_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The instance type supported by the Dedicated Host. For example, <code>m5.large</code>. If the host supports multiple instance types, no <b>instanceType</b> is returned.</p>
    pub fn set_instance_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_type = input;
        self
    }
    /// <p>The instance type supported by the Dedicated Host. For example, <code>m5.large</code>. If the host supports multiple instance types, no <b>instanceType</b> is returned.</p>
    pub fn get_instance_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_type
    }
    /// <p>The instance family supported by the Dedicated Host. For example, <code>m5</code>.</p>
    pub fn instance_family(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_family = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The instance family supported by the Dedicated Host. For example, <code>m5</code>.</p>
    pub fn set_instance_family(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_family = input;
        self
    }
    /// <p>The instance family supported by the Dedicated Host. For example, <code>m5</code>.</p>
    pub fn get_instance_family(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_family
    }
    /// <p>The number of sockets on the Dedicated Host.</p>
    pub fn sockets(mut self, input: i32) -> Self {
        self.sockets = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of sockets on the Dedicated Host.</p>
    pub fn set_sockets(mut self, input: ::std::option::Option<i32>) -> Self {
        self.sockets = input;
        self
    }
    /// <p>The number of sockets on the Dedicated Host.</p>
    pub fn get_sockets(&self) -> &::std::option::Option<i32> {
        &self.sockets
    }
    /// <p>The total number of vCPUs on the Dedicated Host.</p>
    pub fn total_v_cpus(mut self, input: i32) -> Self {
        self.total_v_cpus = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of vCPUs on the Dedicated Host.</p>
    pub fn set_total_v_cpus(mut self, input: ::std::option::Option<i32>) -> Self {
        self.total_v_cpus = input;
        self
    }
    /// <p>The total number of vCPUs on the Dedicated Host.</p>
    pub fn get_total_v_cpus(&self) -> &::std::option::Option<i32> {
        &self.total_v_cpus
    }
    /// Consumes the builder and constructs a [`HostProperties`](crate::types::HostProperties).
    pub fn build(self) -> crate::types::HostProperties {
        crate::types::HostProperties {
            cores: self.cores,
            instance_type: self.instance_type,
            instance_family: self.instance_family,
            sockets: self.sockets,
            total_v_cpus: self.total_v_cpus,
        }
    }
}
