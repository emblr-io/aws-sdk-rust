// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CancelJobInput {
    /// The Job ID of the job to be cancelled.
    pub id: ::std::option::Option<::std::string::String>,
}
impl CancelJobInput {
    /// The Job ID of the job to be cancelled.
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
}
impl CancelJobInput {
    /// Creates a new builder-style object to manufacture [`CancelJobInput`](crate::operation::cancel_job::CancelJobInput).
    pub fn builder() -> crate::operation::cancel_job::builders::CancelJobInputBuilder {
        crate::operation::cancel_job::builders::CancelJobInputBuilder::default()
    }
}

/// A builder for [`CancelJobInput`](crate::operation::cancel_job::CancelJobInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CancelJobInputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
}
impl CancelJobInputBuilder {
    /// The Job ID of the job to be cancelled.
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// The Job ID of the job to be cancelled.
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// The Job ID of the job to be cancelled.
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// Consumes the builder and constructs a [`CancelJobInput`](crate::operation::cancel_job::CancelJobInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::cancel_job::CancelJobInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::cancel_job::CancelJobInput { id: self.id })
    }
}
