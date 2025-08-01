// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartEventDataStoreIngestionInput {
    /// <p>The ARN (or ID suffix of the ARN) of the event data store for which you want to start ingestion.</p>
    pub event_data_store: ::std::option::Option<::std::string::String>,
}
impl StartEventDataStoreIngestionInput {
    /// <p>The ARN (or ID suffix of the ARN) of the event data store for which you want to start ingestion.</p>
    pub fn event_data_store(&self) -> ::std::option::Option<&str> {
        self.event_data_store.as_deref()
    }
}
impl StartEventDataStoreIngestionInput {
    /// Creates a new builder-style object to manufacture [`StartEventDataStoreIngestionInput`](crate::operation::start_event_data_store_ingestion::StartEventDataStoreIngestionInput).
    pub fn builder() -> crate::operation::start_event_data_store_ingestion::builders::StartEventDataStoreIngestionInputBuilder {
        crate::operation::start_event_data_store_ingestion::builders::StartEventDataStoreIngestionInputBuilder::default()
    }
}

/// A builder for [`StartEventDataStoreIngestionInput`](crate::operation::start_event_data_store_ingestion::StartEventDataStoreIngestionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartEventDataStoreIngestionInputBuilder {
    pub(crate) event_data_store: ::std::option::Option<::std::string::String>,
}
impl StartEventDataStoreIngestionInputBuilder {
    /// <p>The ARN (or ID suffix of the ARN) of the event data store for which you want to start ingestion.</p>
    /// This field is required.
    pub fn event_data_store(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.event_data_store = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN (or ID suffix of the ARN) of the event data store for which you want to start ingestion.</p>
    pub fn set_event_data_store(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.event_data_store = input;
        self
    }
    /// <p>The ARN (or ID suffix of the ARN) of the event data store for which you want to start ingestion.</p>
    pub fn get_event_data_store(&self) -> &::std::option::Option<::std::string::String> {
        &self.event_data_store
    }
    /// Consumes the builder and constructs a [`StartEventDataStoreIngestionInput`](crate::operation::start_event_data_store_ingestion::StartEventDataStoreIngestionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::start_event_data_store_ingestion::StartEventDataStoreIngestionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::start_event_data_store_ingestion::StartEventDataStoreIngestionInput {
            event_data_store: self.event_data_store,
        })
    }
}
