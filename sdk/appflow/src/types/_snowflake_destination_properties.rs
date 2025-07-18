// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The properties that are applied when Snowflake is being used as a destination.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SnowflakeDestinationProperties {
    /// <p>The object specified in the Snowflake flow destination.</p>
    pub object: ::std::string::String,
    /// <p>The intermediate bucket that Amazon AppFlow uses when moving data into Snowflake.</p>
    pub intermediate_bucket_name: ::std::string::String,
    /// <p>The object key for the destination bucket in which Amazon AppFlow places the files.</p>
    pub bucket_prefix: ::std::option::Option<::std::string::String>,
    /// <p>The settings that determine how Amazon AppFlow handles an error when placing data in the Snowflake destination. For example, this setting would determine if the flow should fail after one insertion error, or continue and attempt to insert every record regardless of the initial failure. <code>ErrorHandlingConfig</code> is a part of the destination connector details.</p>
    pub error_handling_config: ::std::option::Option<crate::types::ErrorHandlingConfig>,
}
impl SnowflakeDestinationProperties {
    /// <p>The object specified in the Snowflake flow destination.</p>
    pub fn object(&self) -> &str {
        use std::ops::Deref;
        self.object.deref()
    }
    /// <p>The intermediate bucket that Amazon AppFlow uses when moving data into Snowflake.</p>
    pub fn intermediate_bucket_name(&self) -> &str {
        use std::ops::Deref;
        self.intermediate_bucket_name.deref()
    }
    /// <p>The object key for the destination bucket in which Amazon AppFlow places the files.</p>
    pub fn bucket_prefix(&self) -> ::std::option::Option<&str> {
        self.bucket_prefix.as_deref()
    }
    /// <p>The settings that determine how Amazon AppFlow handles an error when placing data in the Snowflake destination. For example, this setting would determine if the flow should fail after one insertion error, or continue and attempt to insert every record regardless of the initial failure. <code>ErrorHandlingConfig</code> is a part of the destination connector details.</p>
    pub fn error_handling_config(&self) -> ::std::option::Option<&crate::types::ErrorHandlingConfig> {
        self.error_handling_config.as_ref()
    }
}
impl SnowflakeDestinationProperties {
    /// Creates a new builder-style object to manufacture [`SnowflakeDestinationProperties`](crate::types::SnowflakeDestinationProperties).
    pub fn builder() -> crate::types::builders::SnowflakeDestinationPropertiesBuilder {
        crate::types::builders::SnowflakeDestinationPropertiesBuilder::default()
    }
}

/// A builder for [`SnowflakeDestinationProperties`](crate::types::SnowflakeDestinationProperties).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SnowflakeDestinationPropertiesBuilder {
    pub(crate) object: ::std::option::Option<::std::string::String>,
    pub(crate) intermediate_bucket_name: ::std::option::Option<::std::string::String>,
    pub(crate) bucket_prefix: ::std::option::Option<::std::string::String>,
    pub(crate) error_handling_config: ::std::option::Option<crate::types::ErrorHandlingConfig>,
}
impl SnowflakeDestinationPropertiesBuilder {
    /// <p>The object specified in the Snowflake flow destination.</p>
    /// This field is required.
    pub fn object(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.object = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The object specified in the Snowflake flow destination.</p>
    pub fn set_object(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.object = input;
        self
    }
    /// <p>The object specified in the Snowflake flow destination.</p>
    pub fn get_object(&self) -> &::std::option::Option<::std::string::String> {
        &self.object
    }
    /// <p>The intermediate bucket that Amazon AppFlow uses when moving data into Snowflake.</p>
    /// This field is required.
    pub fn intermediate_bucket_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.intermediate_bucket_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The intermediate bucket that Amazon AppFlow uses when moving data into Snowflake.</p>
    pub fn set_intermediate_bucket_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.intermediate_bucket_name = input;
        self
    }
    /// <p>The intermediate bucket that Amazon AppFlow uses when moving data into Snowflake.</p>
    pub fn get_intermediate_bucket_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.intermediate_bucket_name
    }
    /// <p>The object key for the destination bucket in which Amazon AppFlow places the files.</p>
    pub fn bucket_prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bucket_prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The object key for the destination bucket in which Amazon AppFlow places the files.</p>
    pub fn set_bucket_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bucket_prefix = input;
        self
    }
    /// <p>The object key for the destination bucket in which Amazon AppFlow places the files.</p>
    pub fn get_bucket_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.bucket_prefix
    }
    /// <p>The settings that determine how Amazon AppFlow handles an error when placing data in the Snowflake destination. For example, this setting would determine if the flow should fail after one insertion error, or continue and attempt to insert every record regardless of the initial failure. <code>ErrorHandlingConfig</code> is a part of the destination connector details.</p>
    pub fn error_handling_config(mut self, input: crate::types::ErrorHandlingConfig) -> Self {
        self.error_handling_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The settings that determine how Amazon AppFlow handles an error when placing data in the Snowflake destination. For example, this setting would determine if the flow should fail after one insertion error, or continue and attempt to insert every record regardless of the initial failure. <code>ErrorHandlingConfig</code> is a part of the destination connector details.</p>
    pub fn set_error_handling_config(mut self, input: ::std::option::Option<crate::types::ErrorHandlingConfig>) -> Self {
        self.error_handling_config = input;
        self
    }
    /// <p>The settings that determine how Amazon AppFlow handles an error when placing data in the Snowflake destination. For example, this setting would determine if the flow should fail after one insertion error, or continue and attempt to insert every record regardless of the initial failure. <code>ErrorHandlingConfig</code> is a part of the destination connector details.</p>
    pub fn get_error_handling_config(&self) -> &::std::option::Option<crate::types::ErrorHandlingConfig> {
        &self.error_handling_config
    }
    /// Consumes the builder and constructs a [`SnowflakeDestinationProperties`](crate::types::SnowflakeDestinationProperties).
    /// This method will fail if any of the following fields are not set:
    /// - [`object`](crate::types::builders::SnowflakeDestinationPropertiesBuilder::object)
    /// - [`intermediate_bucket_name`](crate::types::builders::SnowflakeDestinationPropertiesBuilder::intermediate_bucket_name)
    pub fn build(self) -> ::std::result::Result<crate::types::SnowflakeDestinationProperties, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SnowflakeDestinationProperties {
            object: self.object.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "object",
                    "object was not specified but it is required when building SnowflakeDestinationProperties",
                )
            })?,
            intermediate_bucket_name: self.intermediate_bucket_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "intermediate_bucket_name",
                    "intermediate_bucket_name was not specified but it is required when building SnowflakeDestinationProperties",
                )
            })?,
            bucket_prefix: self.bucket_prefix,
            error_handling_config: self.error_handling_config,
        })
    }
}
