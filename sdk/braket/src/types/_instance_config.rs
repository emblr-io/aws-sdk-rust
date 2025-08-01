// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Configures the resource instances to use while running the Amazon Braket hybrid job on Amazon Braket.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InstanceConfig {
    /// <p>Configures the type resource instances to use while running an Amazon Braket hybrid job.</p>
    pub instance_type: crate::types::InstanceType,
    /// <p>The size of the storage volume, in GB, that user wants to provision.</p>
    pub volume_size_in_gb: i32,
    /// <p>Configures the number of resource instances to use while running an Amazon Braket job on Amazon Braket. The default value is 1.</p>
    pub instance_count: ::std::option::Option<i32>,
}
impl InstanceConfig {
    /// <p>Configures the type resource instances to use while running an Amazon Braket hybrid job.</p>
    pub fn instance_type(&self) -> &crate::types::InstanceType {
        &self.instance_type
    }
    /// <p>The size of the storage volume, in GB, that user wants to provision.</p>
    pub fn volume_size_in_gb(&self) -> i32 {
        self.volume_size_in_gb
    }
    /// <p>Configures the number of resource instances to use while running an Amazon Braket job on Amazon Braket. The default value is 1.</p>
    pub fn instance_count(&self) -> ::std::option::Option<i32> {
        self.instance_count
    }
}
impl InstanceConfig {
    /// Creates a new builder-style object to manufacture [`InstanceConfig`](crate::types::InstanceConfig).
    pub fn builder() -> crate::types::builders::InstanceConfigBuilder {
        crate::types::builders::InstanceConfigBuilder::default()
    }
}

/// A builder for [`InstanceConfig`](crate::types::InstanceConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InstanceConfigBuilder {
    pub(crate) instance_type: ::std::option::Option<crate::types::InstanceType>,
    pub(crate) volume_size_in_gb: ::std::option::Option<i32>,
    pub(crate) instance_count: ::std::option::Option<i32>,
}
impl InstanceConfigBuilder {
    /// <p>Configures the type resource instances to use while running an Amazon Braket hybrid job.</p>
    /// This field is required.
    pub fn instance_type(mut self, input: crate::types::InstanceType) -> Self {
        self.instance_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Configures the type resource instances to use while running an Amazon Braket hybrid job.</p>
    pub fn set_instance_type(mut self, input: ::std::option::Option<crate::types::InstanceType>) -> Self {
        self.instance_type = input;
        self
    }
    /// <p>Configures the type resource instances to use while running an Amazon Braket hybrid job.</p>
    pub fn get_instance_type(&self) -> &::std::option::Option<crate::types::InstanceType> {
        &self.instance_type
    }
    /// <p>The size of the storage volume, in GB, that user wants to provision.</p>
    /// This field is required.
    pub fn volume_size_in_gb(mut self, input: i32) -> Self {
        self.volume_size_in_gb = ::std::option::Option::Some(input);
        self
    }
    /// <p>The size of the storage volume, in GB, that user wants to provision.</p>
    pub fn set_volume_size_in_gb(mut self, input: ::std::option::Option<i32>) -> Self {
        self.volume_size_in_gb = input;
        self
    }
    /// <p>The size of the storage volume, in GB, that user wants to provision.</p>
    pub fn get_volume_size_in_gb(&self) -> &::std::option::Option<i32> {
        &self.volume_size_in_gb
    }
    /// <p>Configures the number of resource instances to use while running an Amazon Braket job on Amazon Braket. The default value is 1.</p>
    pub fn instance_count(mut self, input: i32) -> Self {
        self.instance_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>Configures the number of resource instances to use while running an Amazon Braket job on Amazon Braket. The default value is 1.</p>
    pub fn set_instance_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.instance_count = input;
        self
    }
    /// <p>Configures the number of resource instances to use while running an Amazon Braket job on Amazon Braket. The default value is 1.</p>
    pub fn get_instance_count(&self) -> &::std::option::Option<i32> {
        &self.instance_count
    }
    /// Consumes the builder and constructs a [`InstanceConfig`](crate::types::InstanceConfig).
    /// This method will fail if any of the following fields are not set:
    /// - [`instance_type`](crate::types::builders::InstanceConfigBuilder::instance_type)
    /// - [`volume_size_in_gb`](crate::types::builders::InstanceConfigBuilder::volume_size_in_gb)
    pub fn build(self) -> ::std::result::Result<crate::types::InstanceConfig, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::InstanceConfig {
            instance_type: self.instance_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "instance_type",
                    "instance_type was not specified but it is required when building InstanceConfig",
                )
            })?,
            volume_size_in_gb: self.volume_size_in_gb.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "volume_size_in_gb",
                    "volume_size_in_gb was not specified but it is required when building InstanceConfig",
                )
            })?,
            instance_count: self.instance_count,
        })
    }
}
