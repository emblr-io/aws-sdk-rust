// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The properties that are applied when Amazon Honeycode is used as a destination.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct HoneycodeDestinationProperties {
    /// <p>The object specified in the Amazon Honeycode flow destination.</p>
    pub object: ::std::string::String,
    /// <p>The settings that determine how Amazon AppFlow handles an error when placing data in the destination. For example, this setting would determine if the flow should fail after one insertion error, or continue and attempt to insert every record regardless of the initial failure. <code>ErrorHandlingConfig</code> is a part of the destination connector details.</p>
    pub error_handling_config: ::std::option::Option<crate::types::ErrorHandlingConfig>,
}
impl HoneycodeDestinationProperties {
    /// <p>The object specified in the Amazon Honeycode flow destination.</p>
    pub fn object(&self) -> &str {
        use std::ops::Deref;
        self.object.deref()
    }
    /// <p>The settings that determine how Amazon AppFlow handles an error when placing data in the destination. For example, this setting would determine if the flow should fail after one insertion error, or continue and attempt to insert every record regardless of the initial failure. <code>ErrorHandlingConfig</code> is a part of the destination connector details.</p>
    pub fn error_handling_config(&self) -> ::std::option::Option<&crate::types::ErrorHandlingConfig> {
        self.error_handling_config.as_ref()
    }
}
impl HoneycodeDestinationProperties {
    /// Creates a new builder-style object to manufacture [`HoneycodeDestinationProperties`](crate::types::HoneycodeDestinationProperties).
    pub fn builder() -> crate::types::builders::HoneycodeDestinationPropertiesBuilder {
        crate::types::builders::HoneycodeDestinationPropertiesBuilder::default()
    }
}

/// A builder for [`HoneycodeDestinationProperties`](crate::types::HoneycodeDestinationProperties).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct HoneycodeDestinationPropertiesBuilder {
    pub(crate) object: ::std::option::Option<::std::string::String>,
    pub(crate) error_handling_config: ::std::option::Option<crate::types::ErrorHandlingConfig>,
}
impl HoneycodeDestinationPropertiesBuilder {
    /// <p>The object specified in the Amazon Honeycode flow destination.</p>
    /// This field is required.
    pub fn object(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.object = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The object specified in the Amazon Honeycode flow destination.</p>
    pub fn set_object(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.object = input;
        self
    }
    /// <p>The object specified in the Amazon Honeycode flow destination.</p>
    pub fn get_object(&self) -> &::std::option::Option<::std::string::String> {
        &self.object
    }
    /// <p>The settings that determine how Amazon AppFlow handles an error when placing data in the destination. For example, this setting would determine if the flow should fail after one insertion error, or continue and attempt to insert every record regardless of the initial failure. <code>ErrorHandlingConfig</code> is a part of the destination connector details.</p>
    pub fn error_handling_config(mut self, input: crate::types::ErrorHandlingConfig) -> Self {
        self.error_handling_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The settings that determine how Amazon AppFlow handles an error when placing data in the destination. For example, this setting would determine if the flow should fail after one insertion error, or continue and attempt to insert every record regardless of the initial failure. <code>ErrorHandlingConfig</code> is a part of the destination connector details.</p>
    pub fn set_error_handling_config(mut self, input: ::std::option::Option<crate::types::ErrorHandlingConfig>) -> Self {
        self.error_handling_config = input;
        self
    }
    /// <p>The settings that determine how Amazon AppFlow handles an error when placing data in the destination. For example, this setting would determine if the flow should fail after one insertion error, or continue and attempt to insert every record regardless of the initial failure. <code>ErrorHandlingConfig</code> is a part of the destination connector details.</p>
    pub fn get_error_handling_config(&self) -> &::std::option::Option<crate::types::ErrorHandlingConfig> {
        &self.error_handling_config
    }
    /// Consumes the builder and constructs a [`HoneycodeDestinationProperties`](crate::types::HoneycodeDestinationProperties).
    /// This method will fail if any of the following fields are not set:
    /// - [`object`](crate::types::builders::HoneycodeDestinationPropertiesBuilder::object)
    pub fn build(self) -> ::std::result::Result<crate::types::HoneycodeDestinationProperties, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::HoneycodeDestinationProperties {
            object: self.object.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "object",
                    "object was not specified but it is required when building HoneycodeDestinationProperties",
                )
            })?,
            error_handling_config: self.error_handling_config,
        })
    }
}
