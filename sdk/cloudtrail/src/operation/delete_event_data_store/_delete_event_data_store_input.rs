// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteEventDataStoreInput {
    /// <p>The ARN (or the ID suffix of the ARN) of the event data store to delete.</p>
    pub event_data_store: ::std::option::Option<::std::string::String>,
}
impl DeleteEventDataStoreInput {
    /// <p>The ARN (or the ID suffix of the ARN) of the event data store to delete.</p>
    pub fn event_data_store(&self) -> ::std::option::Option<&str> {
        self.event_data_store.as_deref()
    }
}
impl DeleteEventDataStoreInput {
    /// Creates a new builder-style object to manufacture [`DeleteEventDataStoreInput`](crate::operation::delete_event_data_store::DeleteEventDataStoreInput).
    pub fn builder() -> crate::operation::delete_event_data_store::builders::DeleteEventDataStoreInputBuilder {
        crate::operation::delete_event_data_store::builders::DeleteEventDataStoreInputBuilder::default()
    }
}

/// A builder for [`DeleteEventDataStoreInput`](crate::operation::delete_event_data_store::DeleteEventDataStoreInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteEventDataStoreInputBuilder {
    pub(crate) event_data_store: ::std::option::Option<::std::string::String>,
}
impl DeleteEventDataStoreInputBuilder {
    /// <p>The ARN (or the ID suffix of the ARN) of the event data store to delete.</p>
    /// This field is required.
    pub fn event_data_store(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.event_data_store = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN (or the ID suffix of the ARN) of the event data store to delete.</p>
    pub fn set_event_data_store(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.event_data_store = input;
        self
    }
    /// <p>The ARN (or the ID suffix of the ARN) of the event data store to delete.</p>
    pub fn get_event_data_store(&self) -> &::std::option::Option<::std::string::String> {
        &self.event_data_store
    }
    /// Consumes the builder and constructs a [`DeleteEventDataStoreInput`](crate::operation::delete_event_data_store::DeleteEventDataStoreInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_event_data_store::DeleteEventDataStoreInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::delete_event_data_store::DeleteEventDataStoreInput {
            event_data_store: self.event_data_store,
        })
    }
}
