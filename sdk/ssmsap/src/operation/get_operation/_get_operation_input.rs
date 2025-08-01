// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetOperationInput {
    /// <p>The ID of the operation.</p>
    pub operation_id: ::std::option::Option<::std::string::String>,
}
impl GetOperationInput {
    /// <p>The ID of the operation.</p>
    pub fn operation_id(&self) -> ::std::option::Option<&str> {
        self.operation_id.as_deref()
    }
}
impl GetOperationInput {
    /// Creates a new builder-style object to manufacture [`GetOperationInput`](crate::operation::get_operation::GetOperationInput).
    pub fn builder() -> crate::operation::get_operation::builders::GetOperationInputBuilder {
        crate::operation::get_operation::builders::GetOperationInputBuilder::default()
    }
}

/// A builder for [`GetOperationInput`](crate::operation::get_operation::GetOperationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetOperationInputBuilder {
    pub(crate) operation_id: ::std::option::Option<::std::string::String>,
}
impl GetOperationInputBuilder {
    /// <p>The ID of the operation.</p>
    /// This field is required.
    pub fn operation_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.operation_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the operation.</p>
    pub fn set_operation_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.operation_id = input;
        self
    }
    /// <p>The ID of the operation.</p>
    pub fn get_operation_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.operation_id
    }
    /// Consumes the builder and constructs a [`GetOperationInput`](crate::operation::get_operation::GetOperationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_operation::GetOperationInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_operation::GetOperationInput {
            operation_id: self.operation_id,
        })
    }
}
