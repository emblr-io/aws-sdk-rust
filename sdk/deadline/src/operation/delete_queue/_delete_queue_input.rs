// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteQueueInput {
    /// <p>The ID of the farm from which to remove the queue.</p>
    pub farm_id: ::std::option::Option<::std::string::String>,
    /// <p>The queue ID of the queue to delete.</p>
    pub queue_id: ::std::option::Option<::std::string::String>,
}
impl DeleteQueueInput {
    /// <p>The ID of the farm from which to remove the queue.</p>
    pub fn farm_id(&self) -> ::std::option::Option<&str> {
        self.farm_id.as_deref()
    }
    /// <p>The queue ID of the queue to delete.</p>
    pub fn queue_id(&self) -> ::std::option::Option<&str> {
        self.queue_id.as_deref()
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
    pub(crate) farm_id: ::std::option::Option<::std::string::String>,
    pub(crate) queue_id: ::std::option::Option<::std::string::String>,
}
impl DeleteQueueInputBuilder {
    /// <p>The ID of the farm from which to remove the queue.</p>
    /// This field is required.
    pub fn farm_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.farm_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the farm from which to remove the queue.</p>
    pub fn set_farm_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.farm_id = input;
        self
    }
    /// <p>The ID of the farm from which to remove the queue.</p>
    pub fn get_farm_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.farm_id
    }
    /// <p>The queue ID of the queue to delete.</p>
    /// This field is required.
    pub fn queue_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.queue_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The queue ID of the queue to delete.</p>
    pub fn set_queue_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.queue_id = input;
        self
    }
    /// <p>The queue ID of the queue to delete.</p>
    pub fn get_queue_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.queue_id
    }
    /// Consumes the builder and constructs a [`DeleteQueueInput`](crate::operation::delete_queue::DeleteQueueInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::delete_queue::DeleteQueueInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_queue::DeleteQueueInput {
            farm_id: self.farm_id,
            queue_id: self.queue_id,
        })
    }
}
