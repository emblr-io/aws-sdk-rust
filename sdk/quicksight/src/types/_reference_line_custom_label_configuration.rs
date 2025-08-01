// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The configuration for a custom label on a <code>ReferenceLine</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ReferenceLineCustomLabelConfiguration {
    /// <p>The string text of the custom label.</p>
    pub custom_label: ::std::string::String,
}
impl ReferenceLineCustomLabelConfiguration {
    /// <p>The string text of the custom label.</p>
    pub fn custom_label(&self) -> &str {
        use std::ops::Deref;
        self.custom_label.deref()
    }
}
impl ReferenceLineCustomLabelConfiguration {
    /// Creates a new builder-style object to manufacture [`ReferenceLineCustomLabelConfiguration`](crate::types::ReferenceLineCustomLabelConfiguration).
    pub fn builder() -> crate::types::builders::ReferenceLineCustomLabelConfigurationBuilder {
        crate::types::builders::ReferenceLineCustomLabelConfigurationBuilder::default()
    }
}

/// A builder for [`ReferenceLineCustomLabelConfiguration`](crate::types::ReferenceLineCustomLabelConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ReferenceLineCustomLabelConfigurationBuilder {
    pub(crate) custom_label: ::std::option::Option<::std::string::String>,
}
impl ReferenceLineCustomLabelConfigurationBuilder {
    /// <p>The string text of the custom label.</p>
    /// This field is required.
    pub fn custom_label(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.custom_label = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The string text of the custom label.</p>
    pub fn set_custom_label(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.custom_label = input;
        self
    }
    /// <p>The string text of the custom label.</p>
    pub fn get_custom_label(&self) -> &::std::option::Option<::std::string::String> {
        &self.custom_label
    }
    /// Consumes the builder and constructs a [`ReferenceLineCustomLabelConfiguration`](crate::types::ReferenceLineCustomLabelConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`custom_label`](crate::types::builders::ReferenceLineCustomLabelConfigurationBuilder::custom_label)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::ReferenceLineCustomLabelConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ReferenceLineCustomLabelConfiguration {
            custom_label: self.custom_label.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "custom_label",
                    "custom_label was not specified but it is required when building ReferenceLineCustomLabelConfiguration",
                )
            })?,
        })
    }
}
