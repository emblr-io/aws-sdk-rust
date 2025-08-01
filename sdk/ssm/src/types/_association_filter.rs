// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a filter.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssociationFilter {
    /// <p>The name of the filter.</p><note>
    /// <p><code>InstanceId</code> has been deprecated.</p>
    /// </note>
    pub key: crate::types::AssociationFilterKey,
    /// <p>The filter value.</p>
    pub value: ::std::string::String,
}
impl AssociationFilter {
    /// <p>The name of the filter.</p><note>
    /// <p><code>InstanceId</code> has been deprecated.</p>
    /// </note>
    pub fn key(&self) -> &crate::types::AssociationFilterKey {
        &self.key
    }
    /// <p>The filter value.</p>
    pub fn value(&self) -> &str {
        use std::ops::Deref;
        self.value.deref()
    }
}
impl AssociationFilter {
    /// Creates a new builder-style object to manufacture [`AssociationFilter`](crate::types::AssociationFilter).
    pub fn builder() -> crate::types::builders::AssociationFilterBuilder {
        crate::types::builders::AssociationFilterBuilder::default()
    }
}

/// A builder for [`AssociationFilter`](crate::types::AssociationFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssociationFilterBuilder {
    pub(crate) key: ::std::option::Option<crate::types::AssociationFilterKey>,
    pub(crate) value: ::std::option::Option<::std::string::String>,
}
impl AssociationFilterBuilder {
    /// <p>The name of the filter.</p><note>
    /// <p><code>InstanceId</code> has been deprecated.</p>
    /// </note>
    /// This field is required.
    pub fn key(mut self, input: crate::types::AssociationFilterKey) -> Self {
        self.key = ::std::option::Option::Some(input);
        self
    }
    /// <p>The name of the filter.</p><note>
    /// <p><code>InstanceId</code> has been deprecated.</p>
    /// </note>
    pub fn set_key(mut self, input: ::std::option::Option<crate::types::AssociationFilterKey>) -> Self {
        self.key = input;
        self
    }
    /// <p>The name of the filter.</p><note>
    /// <p><code>InstanceId</code> has been deprecated.</p>
    /// </note>
    pub fn get_key(&self) -> &::std::option::Option<crate::types::AssociationFilterKey> {
        &self.key
    }
    /// <p>The filter value.</p>
    /// This field is required.
    pub fn value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The filter value.</p>
    pub fn set_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.value = input;
        self
    }
    /// <p>The filter value.</p>
    pub fn get_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.value
    }
    /// Consumes the builder and constructs a [`AssociationFilter`](crate::types::AssociationFilter).
    /// This method will fail if any of the following fields are not set:
    /// - [`key`](crate::types::builders::AssociationFilterBuilder::key)
    /// - [`value`](crate::types::builders::AssociationFilterBuilder::value)
    pub fn build(self) -> ::std::result::Result<crate::types::AssociationFilter, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::AssociationFilter {
            key: self.key.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "key",
                    "key was not specified but it is required when building AssociationFilter",
                )
            })?,
            value: self.value.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "value",
                    "value was not specified but it is required when building AssociationFilter",
                )
            })?,
        })
    }
}
