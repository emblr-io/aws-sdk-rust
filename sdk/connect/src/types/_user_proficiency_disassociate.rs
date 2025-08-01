// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about proficiency to be disassociated from the user.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UserProficiencyDisassociate {
    /// <p>The name of user's proficiency.</p>
    pub attribute_name: ::std::string::String,
    /// <p>The value of user's proficiency.</p>
    pub attribute_value: ::std::string::String,
}
impl UserProficiencyDisassociate {
    /// <p>The name of user's proficiency.</p>
    pub fn attribute_name(&self) -> &str {
        use std::ops::Deref;
        self.attribute_name.deref()
    }
    /// <p>The value of user's proficiency.</p>
    pub fn attribute_value(&self) -> &str {
        use std::ops::Deref;
        self.attribute_value.deref()
    }
}
impl UserProficiencyDisassociate {
    /// Creates a new builder-style object to manufacture [`UserProficiencyDisassociate`](crate::types::UserProficiencyDisassociate).
    pub fn builder() -> crate::types::builders::UserProficiencyDisassociateBuilder {
        crate::types::builders::UserProficiencyDisassociateBuilder::default()
    }
}

/// A builder for [`UserProficiencyDisassociate`](crate::types::UserProficiencyDisassociate).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UserProficiencyDisassociateBuilder {
    pub(crate) attribute_name: ::std::option::Option<::std::string::String>,
    pub(crate) attribute_value: ::std::option::Option<::std::string::String>,
}
impl UserProficiencyDisassociateBuilder {
    /// <p>The name of user's proficiency.</p>
    /// This field is required.
    pub fn attribute_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.attribute_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of user's proficiency.</p>
    pub fn set_attribute_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.attribute_name = input;
        self
    }
    /// <p>The name of user's proficiency.</p>
    pub fn get_attribute_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.attribute_name
    }
    /// <p>The value of user's proficiency.</p>
    /// This field is required.
    pub fn attribute_value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.attribute_value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value of user's proficiency.</p>
    pub fn set_attribute_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.attribute_value = input;
        self
    }
    /// <p>The value of user's proficiency.</p>
    pub fn get_attribute_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.attribute_value
    }
    /// Consumes the builder and constructs a [`UserProficiencyDisassociate`](crate::types::UserProficiencyDisassociate).
    /// This method will fail if any of the following fields are not set:
    /// - [`attribute_name`](crate::types::builders::UserProficiencyDisassociateBuilder::attribute_name)
    /// - [`attribute_value`](crate::types::builders::UserProficiencyDisassociateBuilder::attribute_value)
    pub fn build(self) -> ::std::result::Result<crate::types::UserProficiencyDisassociate, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::UserProficiencyDisassociate {
            attribute_name: self.attribute_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "attribute_name",
                    "attribute_name was not specified but it is required when building UserProficiencyDisassociate",
                )
            })?,
            attribute_value: self.attribute_value.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "attribute_value",
                    "attribute_value was not specified but it is required when building UserProficiencyDisassociate",
                )
            })?,
        })
    }
}
