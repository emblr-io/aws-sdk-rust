// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ResetEnabledControlInput {
    /// <p>The ARN of the enabled control to be reset.</p>
    pub enabled_control_identifier: ::std::option::Option<::std::string::String>,
}
impl ResetEnabledControlInput {
    /// <p>The ARN of the enabled control to be reset.</p>
    pub fn enabled_control_identifier(&self) -> ::std::option::Option<&str> {
        self.enabled_control_identifier.as_deref()
    }
}
impl ResetEnabledControlInput {
    /// Creates a new builder-style object to manufacture [`ResetEnabledControlInput`](crate::operation::reset_enabled_control::ResetEnabledControlInput).
    pub fn builder() -> crate::operation::reset_enabled_control::builders::ResetEnabledControlInputBuilder {
        crate::operation::reset_enabled_control::builders::ResetEnabledControlInputBuilder::default()
    }
}

/// A builder for [`ResetEnabledControlInput`](crate::operation::reset_enabled_control::ResetEnabledControlInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ResetEnabledControlInputBuilder {
    pub(crate) enabled_control_identifier: ::std::option::Option<::std::string::String>,
}
impl ResetEnabledControlInputBuilder {
    /// <p>The ARN of the enabled control to be reset.</p>
    /// This field is required.
    pub fn enabled_control_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.enabled_control_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the enabled control to be reset.</p>
    pub fn set_enabled_control_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.enabled_control_identifier = input;
        self
    }
    /// <p>The ARN of the enabled control to be reset.</p>
    pub fn get_enabled_control_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.enabled_control_identifier
    }
    /// Consumes the builder and constructs a [`ResetEnabledControlInput`](crate::operation::reset_enabled_control::ResetEnabledControlInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::reset_enabled_control::ResetEnabledControlInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::reset_enabled_control::ResetEnabledControlInput {
            enabled_control_identifier: self.enabled_control_identifier,
        })
    }
}
