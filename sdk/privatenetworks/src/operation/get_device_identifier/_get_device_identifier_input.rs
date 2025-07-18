// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetDeviceIdentifierInput {
    /// <p>The Amazon Resource Name (ARN) of the device identifier.</p>
    pub device_identifier_arn: ::std::option::Option<::std::string::String>,
}
impl GetDeviceIdentifierInput {
    /// <p>The Amazon Resource Name (ARN) of the device identifier.</p>
    pub fn device_identifier_arn(&self) -> ::std::option::Option<&str> {
        self.device_identifier_arn.as_deref()
    }
}
impl GetDeviceIdentifierInput {
    /// Creates a new builder-style object to manufacture [`GetDeviceIdentifierInput`](crate::operation::get_device_identifier::GetDeviceIdentifierInput).
    pub fn builder() -> crate::operation::get_device_identifier::builders::GetDeviceIdentifierInputBuilder {
        crate::operation::get_device_identifier::builders::GetDeviceIdentifierInputBuilder::default()
    }
}

/// A builder for [`GetDeviceIdentifierInput`](crate::operation::get_device_identifier::GetDeviceIdentifierInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetDeviceIdentifierInputBuilder {
    pub(crate) device_identifier_arn: ::std::option::Option<::std::string::String>,
}
impl GetDeviceIdentifierInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the device identifier.</p>
    /// This field is required.
    pub fn device_identifier_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.device_identifier_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the device identifier.</p>
    pub fn set_device_identifier_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.device_identifier_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the device identifier.</p>
    pub fn get_device_identifier_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.device_identifier_arn
    }
    /// Consumes the builder and constructs a [`GetDeviceIdentifierInput`](crate::operation::get_device_identifier::GetDeviceIdentifierInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_device_identifier::GetDeviceIdentifierInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_device_identifier::GetDeviceIdentifierInput {
            device_identifier_arn: self.device_identifier_arn,
        })
    }
}
