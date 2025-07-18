// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A JSON string which you can use to limit the event bus permissions you are granting to only accounts that fulfill the condition. Currently, the only supported condition is membership in a certain Amazon Web Services organization. The string must contain <code>Type</code>, <code>Key</code>, and <code>Value</code> fields. The <code>Value</code> field specifies the ID of the Amazon Web Services organization. Following is an example value for <code>Condition</code>:</p>
/// <p><code>'{"Type" : "StringEquals", "Key": "aws:PrincipalOrgID", "Value": "o-1234567890"}'</code></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Condition {
    /// <p>Specifies the type of condition. Currently the only supported value is <code>StringEquals</code>.</p>
    pub r#type: ::std::string::String,
    /// <p>Specifies the key for the condition. Currently the only supported key is <code>aws:PrincipalOrgID</code>.</p>
    pub key: ::std::string::String,
    /// <p>Specifies the value for the key. Currently, this must be the ID of the organization.</p>
    pub value: ::std::string::String,
}
impl Condition {
    /// <p>Specifies the type of condition. Currently the only supported value is <code>StringEquals</code>.</p>
    pub fn r#type(&self) -> &str {
        use std::ops::Deref;
        self.r#type.deref()
    }
    /// <p>Specifies the key for the condition. Currently the only supported key is <code>aws:PrincipalOrgID</code>.</p>
    pub fn key(&self) -> &str {
        use std::ops::Deref;
        self.key.deref()
    }
    /// <p>Specifies the value for the key. Currently, this must be the ID of the organization.</p>
    pub fn value(&self) -> &str {
        use std::ops::Deref;
        self.value.deref()
    }
}
impl Condition {
    /// Creates a new builder-style object to manufacture [`Condition`](crate::types::Condition).
    pub fn builder() -> crate::types::builders::ConditionBuilder {
        crate::types::builders::ConditionBuilder::default()
    }
}

/// A builder for [`Condition`](crate::types::Condition).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ConditionBuilder {
    pub(crate) r#type: ::std::option::Option<::std::string::String>,
    pub(crate) key: ::std::option::Option<::std::string::String>,
    pub(crate) value: ::std::option::Option<::std::string::String>,
}
impl ConditionBuilder {
    /// <p>Specifies the type of condition. Currently the only supported value is <code>StringEquals</code>.</p>
    /// This field is required.
    pub fn r#type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.r#type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the type of condition. Currently the only supported value is <code>StringEquals</code>.</p>
    pub fn set_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>Specifies the type of condition. Currently the only supported value is <code>StringEquals</code>.</p>
    pub fn get_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.r#type
    }
    /// <p>Specifies the key for the condition. Currently the only supported key is <code>aws:PrincipalOrgID</code>.</p>
    /// This field is required.
    pub fn key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the key for the condition. Currently the only supported key is <code>aws:PrincipalOrgID</code>.</p>
    pub fn set_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key = input;
        self
    }
    /// <p>Specifies the key for the condition. Currently the only supported key is <code>aws:PrincipalOrgID</code>.</p>
    pub fn get_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.key
    }
    /// <p>Specifies the value for the key. Currently, this must be the ID of the organization.</p>
    /// This field is required.
    pub fn value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the value for the key. Currently, this must be the ID of the organization.</p>
    pub fn set_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.value = input;
        self
    }
    /// <p>Specifies the value for the key. Currently, this must be the ID of the organization.</p>
    pub fn get_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.value
    }
    /// Consumes the builder and constructs a [`Condition`](crate::types::Condition).
    /// This method will fail if any of the following fields are not set:
    /// - [`r#type`](crate::types::builders::ConditionBuilder::type)
    /// - [`key`](crate::types::builders::ConditionBuilder::key)
    /// - [`value`](crate::types::builders::ConditionBuilder::value)
    pub fn build(self) -> ::std::result::Result<crate::types::Condition, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Condition {
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building Condition",
                )
            })?,
            key: self.key.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "key",
                    "key was not specified but it is required when building Condition",
                )
            })?,
            value: self.value.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "value",
                    "value was not specified but it is required when building Condition",
                )
            })?,
        })
    }
}
