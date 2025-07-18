// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details on an Elastic Inference accelerator. For more information, see <a href="https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-inference.html">Working with Amazon Elastic Inference on Amazon ECS</a> in the <i>Amazon Elastic Container Service Developer Guide</i>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InferenceAccelerator {
    /// <p>The Elastic Inference accelerator device name. The <code>deviceName</code> must also be referenced in a container definition as a <a href="https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_ResourceRequirement.html">ResourceRequirement</a>.</p>
    pub device_name: ::std::string::String,
    /// <p>The Elastic Inference accelerator type to use.</p>
    pub device_type: ::std::string::String,
}
impl InferenceAccelerator {
    /// <p>The Elastic Inference accelerator device name. The <code>deviceName</code> must also be referenced in a container definition as a <a href="https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_ResourceRequirement.html">ResourceRequirement</a>.</p>
    pub fn device_name(&self) -> &str {
        use std::ops::Deref;
        self.device_name.deref()
    }
    /// <p>The Elastic Inference accelerator type to use.</p>
    pub fn device_type(&self) -> &str {
        use std::ops::Deref;
        self.device_type.deref()
    }
}
impl InferenceAccelerator {
    /// Creates a new builder-style object to manufacture [`InferenceAccelerator`](crate::types::InferenceAccelerator).
    pub fn builder() -> crate::types::builders::InferenceAcceleratorBuilder {
        crate::types::builders::InferenceAcceleratorBuilder::default()
    }
}

/// A builder for [`InferenceAccelerator`](crate::types::InferenceAccelerator).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InferenceAcceleratorBuilder {
    pub(crate) device_name: ::std::option::Option<::std::string::String>,
    pub(crate) device_type: ::std::option::Option<::std::string::String>,
}
impl InferenceAcceleratorBuilder {
    /// <p>The Elastic Inference accelerator device name. The <code>deviceName</code> must also be referenced in a container definition as a <a href="https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_ResourceRequirement.html">ResourceRequirement</a>.</p>
    /// This field is required.
    pub fn device_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.device_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Elastic Inference accelerator device name. The <code>deviceName</code> must also be referenced in a container definition as a <a href="https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_ResourceRequirement.html">ResourceRequirement</a>.</p>
    pub fn set_device_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.device_name = input;
        self
    }
    /// <p>The Elastic Inference accelerator device name. The <code>deviceName</code> must also be referenced in a container definition as a <a href="https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_ResourceRequirement.html">ResourceRequirement</a>.</p>
    pub fn get_device_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.device_name
    }
    /// <p>The Elastic Inference accelerator type to use.</p>
    /// This field is required.
    pub fn device_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.device_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Elastic Inference accelerator type to use.</p>
    pub fn set_device_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.device_type = input;
        self
    }
    /// <p>The Elastic Inference accelerator type to use.</p>
    pub fn get_device_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.device_type
    }
    /// Consumes the builder and constructs a [`InferenceAccelerator`](crate::types::InferenceAccelerator).
    /// This method will fail if any of the following fields are not set:
    /// - [`device_name`](crate::types::builders::InferenceAcceleratorBuilder::device_name)
    /// - [`device_type`](crate::types::builders::InferenceAcceleratorBuilder::device_type)
    pub fn build(self) -> ::std::result::Result<crate::types::InferenceAccelerator, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::InferenceAccelerator {
            device_name: self.device_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "device_name",
                    "device_name was not specified but it is required when building InferenceAccelerator",
                )
            })?,
            device_type: self.device_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "device_type",
                    "device_type was not specified but it is required when building InferenceAccelerator",
                )
            })?,
        })
    }
}
