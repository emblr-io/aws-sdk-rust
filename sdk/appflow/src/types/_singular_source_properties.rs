// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The properties that are applied when Singular is being used as a source.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SingularSourceProperties {
    /// <p>The object specified in the Singular flow source.</p>
    pub object: ::std::string::String,
}
impl SingularSourceProperties {
    /// <p>The object specified in the Singular flow source.</p>
    pub fn object(&self) -> &str {
        use std::ops::Deref;
        self.object.deref()
    }
}
impl SingularSourceProperties {
    /// Creates a new builder-style object to manufacture [`SingularSourceProperties`](crate::types::SingularSourceProperties).
    pub fn builder() -> crate::types::builders::SingularSourcePropertiesBuilder {
        crate::types::builders::SingularSourcePropertiesBuilder::default()
    }
}

/// A builder for [`SingularSourceProperties`](crate::types::SingularSourceProperties).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SingularSourcePropertiesBuilder {
    pub(crate) object: ::std::option::Option<::std::string::String>,
}
impl SingularSourcePropertiesBuilder {
    /// <p>The object specified in the Singular flow source.</p>
    /// This field is required.
    pub fn object(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.object = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The object specified in the Singular flow source.</p>
    pub fn set_object(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.object = input;
        self
    }
    /// <p>The object specified in the Singular flow source.</p>
    pub fn get_object(&self) -> &::std::option::Option<::std::string::String> {
        &self.object
    }
    /// Consumes the builder and constructs a [`SingularSourceProperties`](crate::types::SingularSourceProperties).
    /// This method will fail if any of the following fields are not set:
    /// - [`object`](crate::types::builders::SingularSourcePropertiesBuilder::object)
    pub fn build(self) -> ::std::result::Result<crate::types::SingularSourceProperties, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SingularSourceProperties {
            object: self.object.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "object",
                    "object was not specified but it is required when building SingularSourceProperties",
                )
            })?,
        })
    }
}
