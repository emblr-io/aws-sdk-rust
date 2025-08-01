// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RestoreEventDataStoreInput {
    /// <p>The ARN (or the ID suffix of the ARN) of the event data store that you want to restore.</p>
    pub event_data_store: ::std::option::Option<::std::string::String>,
}
impl RestoreEventDataStoreInput {
    /// <p>The ARN (or the ID suffix of the ARN) of the event data store that you want to restore.</p>
    pub fn event_data_store(&self) -> ::std::option::Option<&str> {
        self.event_data_store.as_deref()
    }
}
impl RestoreEventDataStoreInput {
    /// Creates a new builder-style object to manufacture [`RestoreEventDataStoreInput`](crate::operation::restore_event_data_store::RestoreEventDataStoreInput).
    pub fn builder() -> crate::operation::restore_event_data_store::builders::RestoreEventDataStoreInputBuilder {
        crate::operation::restore_event_data_store::builders::RestoreEventDataStoreInputBuilder::default()
    }
}

/// A builder for [`RestoreEventDataStoreInput`](crate::operation::restore_event_data_store::RestoreEventDataStoreInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RestoreEventDataStoreInputBuilder {
    pub(crate) event_data_store: ::std::option::Option<::std::string::String>,
}
impl RestoreEventDataStoreInputBuilder {
    /// <p>The ARN (or the ID suffix of the ARN) of the event data store that you want to restore.</p>
    /// This field is required.
    pub fn event_data_store(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.event_data_store = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN (or the ID suffix of the ARN) of the event data store that you want to restore.</p>
    pub fn set_event_data_store(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.event_data_store = input;
        self
    }
    /// <p>The ARN (or the ID suffix of the ARN) of the event data store that you want to restore.</p>
    pub fn get_event_data_store(&self) -> &::std::option::Option<::std::string::String> {
        &self.event_data_store
    }
    /// Consumes the builder and constructs a [`RestoreEventDataStoreInput`](crate::operation::restore_event_data_store::RestoreEventDataStoreInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::restore_event_data_store::RestoreEventDataStoreInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::restore_event_data_store::RestoreEventDataStoreInput {
            event_data_store: self.event_data_store,
        })
    }
}
