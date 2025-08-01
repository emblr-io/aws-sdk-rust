// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteQueueInput {
    /// The name of the queue that you want to delete.
    pub name: ::std::option::Option<::std::string::String>,
}
impl DeleteQueueInput {
    /// The name of the queue that you want to delete.
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
}
impl DeleteQueueInput {
    /// Creates a new builder-style object to manufacture [`DeleteQueueInput`](crate::operation::delete_queue::DeleteQueueInput).
    pub fn builder() -> crate::operation::delete_queue::builders::DeleteQueueInputBuilder {
        crate::operation::delete_queue::builders::DeleteQueueInputBuilder::default()
    }
}

/// A builder for [`DeleteQueueInput`](crate::operation::delete_queue::DeleteQueueInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteQueueInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl DeleteQueueInputBuilder {
    /// The name of the queue that you want to delete.
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// The name of the queue that you want to delete.
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// The name of the queue that you want to delete.
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`DeleteQueueInput`](crate::operation::delete_queue::DeleteQueueInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::delete_queue::DeleteQueueInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_queue::DeleteQueueInput { name: self.name })
    }
}
