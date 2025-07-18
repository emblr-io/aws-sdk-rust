// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateIngestionDestinationOutput {
    /// <p>Contains information about an ingestion destination.</p>
    pub ingestion_destination: ::std::option::Option<crate::types::IngestionDestination>,
    _request_id: Option<String>,
}
impl UpdateIngestionDestinationOutput {
    /// <p>Contains information about an ingestion destination.</p>
    pub fn ingestion_destination(&self) -> ::std::option::Option<&crate::types::IngestionDestination> {
        self.ingestion_destination.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateIngestionDestinationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateIngestionDestinationOutput {
    /// Creates a new builder-style object to manufacture [`UpdateIngestionDestinationOutput`](crate::operation::update_ingestion_destination::UpdateIngestionDestinationOutput).
    pub fn builder() -> crate::operation::update_ingestion_destination::builders::UpdateIngestionDestinationOutputBuilder {
        crate::operation::update_ingestion_destination::builders::UpdateIngestionDestinationOutputBuilder::default()
    }
}

/// A builder for [`UpdateIngestionDestinationOutput`](crate::operation::update_ingestion_destination::UpdateIngestionDestinationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateIngestionDestinationOutputBuilder {
    pub(crate) ingestion_destination: ::std::option::Option<crate::types::IngestionDestination>,
    _request_id: Option<String>,
}
impl UpdateIngestionDestinationOutputBuilder {
    /// <p>Contains information about an ingestion destination.</p>
    /// This field is required.
    pub fn ingestion_destination(mut self, input: crate::types::IngestionDestination) -> Self {
        self.ingestion_destination = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains information about an ingestion destination.</p>
    pub fn set_ingestion_destination(mut self, input: ::std::option::Option<crate::types::IngestionDestination>) -> Self {
        self.ingestion_destination = input;
        self
    }
    /// <p>Contains information about an ingestion destination.</p>
    pub fn get_ingestion_destination(&self) -> &::std::option::Option<crate::types::IngestionDestination> {
        &self.ingestion_destination
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateIngestionDestinationOutput`](crate::operation::update_ingestion_destination::UpdateIngestionDestinationOutput).
    pub fn build(self) -> crate::operation::update_ingestion_destination::UpdateIngestionDestinationOutput {
        crate::operation::update_ingestion_destination::UpdateIngestionDestinationOutput {
            ingestion_destination: self.ingestion_destination,
            _request_id: self._request_id,
        }
    }
}
