// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about a Greengrass core device, which is an IoT thing that runs the IoT Greengrass Core software.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CoreDevice {
    /// <p>The name of the core device. This is also the name of the IoT thing.</p>
    pub core_device_thing_name: ::std::option::Option<::std::string::String>,
    /// <p>The status of the core device. Core devices can have the following statuses:</p>
    /// <ul>
    /// <li>
    /// <p><code>HEALTHY</code> – The IoT Greengrass Core software and all components run on the core device without issue.</p></li>
    /// <li>
    /// <p><code>UNHEALTHY</code> – The IoT Greengrass Core software or a component is in a failed state on the core device.</p></li>
    /// </ul>
    pub status: ::std::option::Option<crate::types::CoreDeviceStatus>,
    /// <p>The time at which the core device's status last updated, expressed in ISO 8601 format.</p>
    pub last_status_update_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The operating system platform that the core device runs.</p>
    pub platform: ::std::option::Option<::std::string::String>,
    /// <p>The computer architecture of the core device.</p>
    pub architecture: ::std::option::Option<::std::string::String>,
    /// <p>The runtime for the core device. The runtime can be:</p>
    /// <ul>
    /// <li>
    /// <p><code>aws_nucleus_classic</code></p></li>
    /// <li>
    /// <p><code>aws_nucleus_lite</code></p></li>
    /// </ul>
    pub runtime: ::std::option::Option<::std::string::String>,
}
impl CoreDevice {
    /// <p>The name of the core device. This is also the name of the IoT thing.</p>
    pub fn core_device_thing_name(&self) -> ::std::option::Option<&str> {
        self.core_device_thing_name.as_deref()
    }
    /// <p>The status of the core device. Core devices can have the following statuses:</p>
    /// <ul>
    /// <li>
    /// <p><code>HEALTHY</code> – The IoT Greengrass Core software and all components run on the core device without issue.</p></li>
    /// <li>
    /// <p><code>UNHEALTHY</code> – The IoT Greengrass Core software or a component is in a failed state on the core device.</p></li>
    /// </ul>
    pub fn status(&self) -> ::std::option::Option<&crate::types::CoreDeviceStatus> {
        self.status.as_ref()
    }
    /// <p>The time at which the core device's status last updated, expressed in ISO 8601 format.</p>
    pub fn last_status_update_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_status_update_timestamp.as_ref()
    }
    /// <p>The operating system platform that the core device runs.</p>
    pub fn platform(&self) -> ::std::option::Option<&str> {
        self.platform.as_deref()
    }
    /// <p>The computer architecture of the core device.</p>
    pub fn architecture(&self) -> ::std::option::Option<&str> {
        self.architecture.as_deref()
    }
    /// <p>The runtime for the core device. The runtime can be:</p>
    /// <ul>
    /// <li>
    /// <p><code>aws_nucleus_classic</code></p></li>
    /// <li>
    /// <p><code>aws_nucleus_lite</code></p></li>
    /// </ul>
    pub fn runtime(&self) -> ::std::option::Option<&str> {
        self.runtime.as_deref()
    }
}
impl CoreDevice {
    /// Creates a new builder-style object to manufacture [`CoreDevice`](crate::types::CoreDevice).
    pub fn builder() -> crate::types::builders::CoreDeviceBuilder {
        crate::types::builders::CoreDeviceBuilder::default()
    }
}

/// A builder for [`CoreDevice`](crate::types::CoreDevice).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CoreDeviceBuilder {
    pub(crate) core_device_thing_name: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::CoreDeviceStatus>,
    pub(crate) last_status_update_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) platform: ::std::option::Option<::std::string::String>,
    pub(crate) architecture: ::std::option::Option<::std::string::String>,
    pub(crate) runtime: ::std::option::Option<::std::string::String>,
}
impl CoreDeviceBuilder {
    /// <p>The name of the core device. This is also the name of the IoT thing.</p>
    pub fn core_device_thing_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.core_device_thing_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the core device. This is also the name of the IoT thing.</p>
    pub fn set_core_device_thing_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.core_device_thing_name = input;
        self
    }
    /// <p>The name of the core device. This is also the name of the IoT thing.</p>
    pub fn get_core_device_thing_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.core_device_thing_name
    }
    /// <p>The status of the core device. Core devices can have the following statuses:</p>
    /// <ul>
    /// <li>
    /// <p><code>HEALTHY</code> – The IoT Greengrass Core software and all components run on the core device without issue.</p></li>
    /// <li>
    /// <p><code>UNHEALTHY</code> – The IoT Greengrass Core software or a component is in a failed state on the core device.</p></li>
    /// </ul>
    pub fn status(mut self, input: crate::types::CoreDeviceStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the core device. Core devices can have the following statuses:</p>
    /// <ul>
    /// <li>
    /// <p><code>HEALTHY</code> – The IoT Greengrass Core software and all components run on the core device without issue.</p></li>
    /// <li>
    /// <p><code>UNHEALTHY</code> – The IoT Greengrass Core software or a component is in a failed state on the core device.</p></li>
    /// </ul>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::CoreDeviceStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the core device. Core devices can have the following statuses:</p>
    /// <ul>
    /// <li>
    /// <p><code>HEALTHY</code> – The IoT Greengrass Core software and all components run on the core device without issue.</p></li>
    /// <li>
    /// <p><code>UNHEALTHY</code> – The IoT Greengrass Core software or a component is in a failed state on the core device.</p></li>
    /// </ul>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::CoreDeviceStatus> {
        &self.status
    }
    /// <p>The time at which the core device's status last updated, expressed in ISO 8601 format.</p>
    pub fn last_status_update_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_status_update_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time at which the core device's status last updated, expressed in ISO 8601 format.</p>
    pub fn set_last_status_update_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_status_update_timestamp = input;
        self
    }
    /// <p>The time at which the core device's status last updated, expressed in ISO 8601 format.</p>
    pub fn get_last_status_update_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_status_update_timestamp
    }
    /// <p>The operating system platform that the core device runs.</p>
    pub fn platform(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.platform = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The operating system platform that the core device runs.</p>
    pub fn set_platform(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.platform = input;
        self
    }
    /// <p>The operating system platform that the core device runs.</p>
    pub fn get_platform(&self) -> &::std::option::Option<::std::string::String> {
        &self.platform
    }
    /// <p>The computer architecture of the core device.</p>
    pub fn architecture(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.architecture = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The computer architecture of the core device.</p>
    pub fn set_architecture(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.architecture = input;
        self
    }
    /// <p>The computer architecture of the core device.</p>
    pub fn get_architecture(&self) -> &::std::option::Option<::std::string::String> {
        &self.architecture
    }
    /// <p>The runtime for the core device. The runtime can be:</p>
    /// <ul>
    /// <li>
    /// <p><code>aws_nucleus_classic</code></p></li>
    /// <li>
    /// <p><code>aws_nucleus_lite</code></p></li>
    /// </ul>
    pub fn runtime(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.runtime = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The runtime for the core device. The runtime can be:</p>
    /// <ul>
    /// <li>
    /// <p><code>aws_nucleus_classic</code></p></li>
    /// <li>
    /// <p><code>aws_nucleus_lite</code></p></li>
    /// </ul>
    pub fn set_runtime(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.runtime = input;
        self
    }
    /// <p>The runtime for the core device. The runtime can be:</p>
    /// <ul>
    /// <li>
    /// <p><code>aws_nucleus_classic</code></p></li>
    /// <li>
    /// <p><code>aws_nucleus_lite</code></p></li>
    /// </ul>
    pub fn get_runtime(&self) -> &::std::option::Option<::std::string::String> {
        &self.runtime
    }
    /// Consumes the builder and constructs a [`CoreDevice`](crate::types::CoreDevice).
    pub fn build(self) -> crate::types::CoreDevice {
        crate::types::CoreDevice {
            core_device_thing_name: self.core_device_thing_name,
            status: self.status,
            last_status_update_timestamp: self.last_status_update_timestamp,
            platform: self.platform,
            architecture: self.architecture,
            runtime: self.runtime,
        }
    }
}
