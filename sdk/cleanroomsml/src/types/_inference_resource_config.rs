// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Defines the resources used to perform model inference.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InferenceResourceConfig {
    /// <p>The type of instance that is used to perform model inference.</p>
    pub instance_type: crate::types::InferenceInstanceType,
    /// <p>The number of instances to use.</p>
    pub instance_count: i32,
}
impl InferenceResourceConfig {
    /// <p>The type of instance that is used to perform model inference.</p>
    pub fn instance_type(&self) -> &crate::types::InferenceInstanceType {
        &self.instance_type
    }
    /// <p>The number of instances to use.</p>
    pub fn instance_count(&self) -> i32 {
        self.instance_count
    }
}
impl InferenceResourceConfig {
    /// Creates a new builder-style object to manufacture [`InferenceResourceConfig`](crate::types::InferenceResourceConfig).
    pub fn builder() -> crate::types::builders::InferenceResourceConfigBuilder {
        crate::types::builders::InferenceResourceConfigBuilder::default()
    }
}

/// A builder for [`InferenceResourceConfig`](crate::types::InferenceResourceConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InferenceResourceConfigBuilder {
    pub(crate) instance_type: ::std::option::Option<crate::types::InferenceInstanceType>,
    pub(crate) instance_count: ::std::option::Option<i32>,
}
impl InferenceResourceConfigBuilder {
    /// <p>The type of instance that is used to perform model inference.</p>
    /// This field is required.
    pub fn instance_type(mut self, input: crate::types::InferenceInstanceType) -> Self {
        self.instance_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of instance that is used to perform model inference.</p>
    pub fn set_instance_type(mut self, input: ::std::option::Option<crate::types::InferenceInstanceType>) -> Self {
        self.instance_type = input;
        self
    }
    /// <p>The type of instance that is used to perform model inference.</p>
    pub fn get_instance_type(&self) -> &::std::option::Option<crate::types::InferenceInstanceType> {
        &self.instance_type
    }
    /// <p>The number of instances to use.</p>
    pub fn instance_count(mut self, input: i32) -> Self {
        self.instance_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of instances to use.</p>
    pub fn set_instance_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.instance_count = input;
        self
    }
    /// <p>The number of instances to use.</p>
    pub fn get_instance_count(&self) -> &::std::option::Option<i32> {
        &self.instance_count
    }
    /// Consumes the builder and constructs a [`InferenceResourceConfig`](crate::types::InferenceResourceConfig).
    /// This method will fail if any of the following fields are not set:
    /// - [`instance_type`](crate::types::builders::InferenceResourceConfigBuilder::instance_type)
    pub fn build(self) -> ::std::result::Result<crate::types::InferenceResourceConfig, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::InferenceResourceConfig {
            instance_type: self.instance_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "instance_type",
                    "instance_type was not specified but it is required when building InferenceResourceConfig",
                )
            })?,
            instance_count: self.instance_count.unwrap_or(1),
        })
    }
}
