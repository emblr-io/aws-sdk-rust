// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The devices that are available on the container instance. The only supported device type is a GPU.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PlatformDevice {
    /// <p>The ID for the GPUs on the container instance. The available GPU IDs can also be obtained on the container instance in the <code>/var/lib/ecs/gpu/nvidia_gpu_info.json</code> file.</p>
    pub id: ::std::string::String,
    /// <p>The type of device that's available on the container instance. The only supported value is <code>GPU</code>.</p>
    pub r#type: crate::types::PlatformDeviceType,
}
impl PlatformDevice {
    /// <p>The ID for the GPUs on the container instance. The available GPU IDs can also be obtained on the container instance in the <code>/var/lib/ecs/gpu/nvidia_gpu_info.json</code> file.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>The type of device that's available on the container instance. The only supported value is <code>GPU</code>.</p>
    pub fn r#type(&self) -> &crate::types::PlatformDeviceType {
        &self.r#type
    }
}
impl PlatformDevice {
    /// Creates a new builder-style object to manufacture [`PlatformDevice`](crate::types::PlatformDevice).
    pub fn builder() -> crate::types::builders::PlatformDeviceBuilder {
        crate::types::builders::PlatformDeviceBuilder::default()
    }
}

/// A builder for [`PlatformDevice`](crate::types::PlatformDevice).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PlatformDeviceBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::PlatformDeviceType>,
}
impl PlatformDeviceBuilder {
    /// <p>The ID for the GPUs on the container instance. The available GPU IDs can also be obtained on the container instance in the <code>/var/lib/ecs/gpu/nvidia_gpu_info.json</code> file.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID for the GPUs on the container instance. The available GPU IDs can also be obtained on the container instance in the <code>/var/lib/ecs/gpu/nvidia_gpu_info.json</code> file.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID for the GPUs on the container instance. The available GPU IDs can also be obtained on the container instance in the <code>/var/lib/ecs/gpu/nvidia_gpu_info.json</code> file.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The type of device that's available on the container instance. The only supported value is <code>GPU</code>.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::PlatformDeviceType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of device that's available on the container instance. The only supported value is <code>GPU</code>.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::PlatformDeviceType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of device that's available on the container instance. The only supported value is <code>GPU</code>.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::PlatformDeviceType> {
        &self.r#type
    }
    /// Consumes the builder and constructs a [`PlatformDevice`](crate::types::PlatformDevice).
    /// This method will fail if any of the following fields are not set:
    /// - [`id`](crate::types::builders::PlatformDeviceBuilder::id)
    /// - [`r#type`](crate::types::builders::PlatformDeviceBuilder::type)
    pub fn build(self) -> ::std::result::Result<crate::types::PlatformDevice, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::PlatformDevice {
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building PlatformDevice",
                )
            })?,
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building PlatformDevice",
                )
            })?,
        })
    }
}
