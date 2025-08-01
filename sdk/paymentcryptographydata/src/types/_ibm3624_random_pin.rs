// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Parameters that are required to generate or verify Ibm3624 random PIN.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct Ibm3624RandomPin {
    /// <p>The decimalization table to use for IBM 3624 PIN algorithm. The table is used to convert the algorithm intermediate result from hexadecimal characters to decimal.</p>
    pub decimalization_table: ::std::string::String,
    /// <p>The padding character for validation data.</p>
    pub pin_validation_data_pad_character: ::std::string::String,
    /// <p>The unique data for cardholder identification.</p>
    pub pin_validation_data: ::std::string::String,
}
impl Ibm3624RandomPin {
    /// <p>The decimalization table to use for IBM 3624 PIN algorithm. The table is used to convert the algorithm intermediate result from hexadecimal characters to decimal.</p>
    pub fn decimalization_table(&self) -> &str {
        use std::ops::Deref;
        self.decimalization_table.deref()
    }
    /// <p>The padding character for validation data.</p>
    pub fn pin_validation_data_pad_character(&self) -> &str {
        use std::ops::Deref;
        self.pin_validation_data_pad_character.deref()
    }
    /// <p>The unique data for cardholder identification.</p>
    pub fn pin_validation_data(&self) -> &str {
        use std::ops::Deref;
        self.pin_validation_data.deref()
    }
}
impl ::std::fmt::Debug for Ibm3624RandomPin {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("Ibm3624RandomPin");
        formatter.field("decimalization_table", &"*** Sensitive Data Redacted ***");
        formatter.field("pin_validation_data_pad_character", &self.pin_validation_data_pad_character);
        formatter.field("pin_validation_data", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl Ibm3624RandomPin {
    /// Creates a new builder-style object to manufacture [`Ibm3624RandomPin`](crate::types::Ibm3624RandomPin).
    pub fn builder() -> crate::types::builders::Ibm3624RandomPinBuilder {
        crate::types::builders::Ibm3624RandomPinBuilder::default()
    }
}

/// A builder for [`Ibm3624RandomPin`](crate::types::Ibm3624RandomPin).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct Ibm3624RandomPinBuilder {
    pub(crate) decimalization_table: ::std::option::Option<::std::string::String>,
    pub(crate) pin_validation_data_pad_character: ::std::option::Option<::std::string::String>,
    pub(crate) pin_validation_data: ::std::option::Option<::std::string::String>,
}
impl Ibm3624RandomPinBuilder {
    /// <p>The decimalization table to use for IBM 3624 PIN algorithm. The table is used to convert the algorithm intermediate result from hexadecimal characters to decimal.</p>
    /// This field is required.
    pub fn decimalization_table(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.decimalization_table = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The decimalization table to use for IBM 3624 PIN algorithm. The table is used to convert the algorithm intermediate result from hexadecimal characters to decimal.</p>
    pub fn set_decimalization_table(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.decimalization_table = input;
        self
    }
    /// <p>The decimalization table to use for IBM 3624 PIN algorithm. The table is used to convert the algorithm intermediate result from hexadecimal characters to decimal.</p>
    pub fn get_decimalization_table(&self) -> &::std::option::Option<::std::string::String> {
        &self.decimalization_table
    }
    /// <p>The padding character for validation data.</p>
    /// This field is required.
    pub fn pin_validation_data_pad_character(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.pin_validation_data_pad_character = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The padding character for validation data.</p>
    pub fn set_pin_validation_data_pad_character(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.pin_validation_data_pad_character = input;
        self
    }
    /// <p>The padding character for validation data.</p>
    pub fn get_pin_validation_data_pad_character(&self) -> &::std::option::Option<::std::string::String> {
        &self.pin_validation_data_pad_character
    }
    /// <p>The unique data for cardholder identification.</p>
    /// This field is required.
    pub fn pin_validation_data(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.pin_validation_data = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique data for cardholder identification.</p>
    pub fn set_pin_validation_data(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.pin_validation_data = input;
        self
    }
    /// <p>The unique data for cardholder identification.</p>
    pub fn get_pin_validation_data(&self) -> &::std::option::Option<::std::string::String> {
        &self.pin_validation_data
    }
    /// Consumes the builder and constructs a [`Ibm3624RandomPin`](crate::types::Ibm3624RandomPin).
    /// This method will fail if any of the following fields are not set:
    /// - [`decimalization_table`](crate::types::builders::Ibm3624RandomPinBuilder::decimalization_table)
    /// - [`pin_validation_data_pad_character`](crate::types::builders::Ibm3624RandomPinBuilder::pin_validation_data_pad_character)
    /// - [`pin_validation_data`](crate::types::builders::Ibm3624RandomPinBuilder::pin_validation_data)
    pub fn build(self) -> ::std::result::Result<crate::types::Ibm3624RandomPin, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Ibm3624RandomPin {
            decimalization_table: self.decimalization_table.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "decimalization_table",
                    "decimalization_table was not specified but it is required when building Ibm3624RandomPin",
                )
            })?,
            pin_validation_data_pad_character: self.pin_validation_data_pad_character.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "pin_validation_data_pad_character",
                    "pin_validation_data_pad_character was not specified but it is required when building Ibm3624RandomPin",
                )
            })?,
            pin_validation_data: self.pin_validation_data.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "pin_validation_data",
                    "pin_validation_data was not specified but it is required when building Ibm3624RandomPin",
                )
            })?,
        })
    }
}
impl ::std::fmt::Debug for Ibm3624RandomPinBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("Ibm3624RandomPinBuilder");
        formatter.field("decimalization_table", &"*** Sensitive Data Redacted ***");
        formatter.field("pin_validation_data_pad_character", &self.pin_validation_data_pad_character);
        formatter.field("pin_validation_data", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
