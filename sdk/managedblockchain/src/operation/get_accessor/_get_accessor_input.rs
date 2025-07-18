// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetAccessorInput {
    /// <p>The unique identifier of the accessor.</p>
    pub accessor_id: ::std::option::Option<::std::string::String>,
}
impl GetAccessorInput {
    /// <p>The unique identifier of the accessor.</p>
    pub fn accessor_id(&self) -> ::std::option::Option<&str> {
        self.accessor_id.as_deref()
    }
}
impl GetAccessorInput {
    /// Creates a new builder-style object to manufacture [`GetAccessorInput`](crate::operation::get_accessor::GetAccessorInput).
    pub fn builder() -> crate::operation::get_accessor::builders::GetAccessorInputBuilder {
        crate::operation::get_accessor::builders::GetAccessorInputBuilder::default()
    }
}

/// A builder for [`GetAccessorInput`](crate::operation::get_accessor::GetAccessorInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetAccessorInputBuilder {
    pub(crate) accessor_id: ::std::option::Option<::std::string::String>,
}
impl GetAccessorInputBuilder {
    /// <p>The unique identifier of the accessor.</p>
    /// This field is required.
    pub fn accessor_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.accessor_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the accessor.</p>
    pub fn set_accessor_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.accessor_id = input;
        self
    }
    /// <p>The unique identifier of the accessor.</p>
    pub fn get_accessor_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.accessor_id
    }
    /// Consumes the builder and constructs a [`GetAccessorInput`](crate::operation::get_accessor::GetAccessorInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::get_accessor::GetAccessorInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_accessor::GetAccessorInput {
            accessor_id: self.accessor_id,
        })
    }
}
