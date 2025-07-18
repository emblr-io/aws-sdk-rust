// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <note>
/// <p>Amazon Elastic Inference is no longer available.</p>
/// </note>
/// <p>Describes an elastic inference accelerator.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LaunchTemplateElasticInferenceAccelerator {
    /// <p>The type of elastic inference accelerator. The possible values are eia1.medium, eia1.large, and eia1.xlarge.</p>
    pub r#type: ::std::option::Option<::std::string::String>,
    /// <p>The number of elastic inference accelerators to attach to the instance.</p>
    /// <p>Default: 1</p>
    pub count: ::std::option::Option<i32>,
}
impl LaunchTemplateElasticInferenceAccelerator {
    /// <p>The type of elastic inference accelerator. The possible values are eia1.medium, eia1.large, and eia1.xlarge.</p>
    pub fn r#type(&self) -> ::std::option::Option<&str> {
        self.r#type.as_deref()
    }
    /// <p>The number of elastic inference accelerators to attach to the instance.</p>
    /// <p>Default: 1</p>
    pub fn count(&self) -> ::std::option::Option<i32> {
        self.count
    }
}
impl LaunchTemplateElasticInferenceAccelerator {
    /// Creates a new builder-style object to manufacture [`LaunchTemplateElasticInferenceAccelerator`](crate::types::LaunchTemplateElasticInferenceAccelerator).
    pub fn builder() -> crate::types::builders::LaunchTemplateElasticInferenceAcceleratorBuilder {
        crate::types::builders::LaunchTemplateElasticInferenceAcceleratorBuilder::default()
    }
}

/// A builder for [`LaunchTemplateElasticInferenceAccelerator`](crate::types::LaunchTemplateElasticInferenceAccelerator).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LaunchTemplateElasticInferenceAcceleratorBuilder {
    pub(crate) r#type: ::std::option::Option<::std::string::String>,
    pub(crate) count: ::std::option::Option<i32>,
}
impl LaunchTemplateElasticInferenceAcceleratorBuilder {
    /// <p>The type of elastic inference accelerator. The possible values are eia1.medium, eia1.large, and eia1.xlarge.</p>
    /// This field is required.
    pub fn r#type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.r#type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of elastic inference accelerator. The possible values are eia1.medium, eia1.large, and eia1.xlarge.</p>
    pub fn set_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of elastic inference accelerator. The possible values are eia1.medium, eia1.large, and eia1.xlarge.</p>
    pub fn get_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.r#type
    }
    /// <p>The number of elastic inference accelerators to attach to the instance.</p>
    /// <p>Default: 1</p>
    pub fn count(mut self, input: i32) -> Self {
        self.count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of elastic inference accelerators to attach to the instance.</p>
    /// <p>Default: 1</p>
    pub fn set_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.count = input;
        self
    }
    /// <p>The number of elastic inference accelerators to attach to the instance.</p>
    /// <p>Default: 1</p>
    pub fn get_count(&self) -> &::std::option::Option<i32> {
        &self.count
    }
    /// Consumes the builder and constructs a [`LaunchTemplateElasticInferenceAccelerator`](crate::types::LaunchTemplateElasticInferenceAccelerator).
    pub fn build(self) -> crate::types::LaunchTemplateElasticInferenceAccelerator {
        crate::types::LaunchTemplateElasticInferenceAccelerator {
            r#type: self.r#type,
            count: self.count,
        }
    }
}
