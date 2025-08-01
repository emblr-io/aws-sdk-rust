// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteJourneyOutput {
    /// <p>Provides information about the status, configuration, and other settings for a journey.</p>
    pub journey_response: ::std::option::Option<crate::types::JourneyResponse>,
    _request_id: Option<String>,
}
impl DeleteJourneyOutput {
    /// <p>Provides information about the status, configuration, and other settings for a journey.</p>
    pub fn journey_response(&self) -> ::std::option::Option<&crate::types::JourneyResponse> {
        self.journey_response.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DeleteJourneyOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteJourneyOutput {
    /// Creates a new builder-style object to manufacture [`DeleteJourneyOutput`](crate::operation::delete_journey::DeleteJourneyOutput).
    pub fn builder() -> crate::operation::delete_journey::builders::DeleteJourneyOutputBuilder {
        crate::operation::delete_journey::builders::DeleteJourneyOutputBuilder::default()
    }
}

/// A builder for [`DeleteJourneyOutput`](crate::operation::delete_journey::DeleteJourneyOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteJourneyOutputBuilder {
    pub(crate) journey_response: ::std::option::Option<crate::types::JourneyResponse>,
    _request_id: Option<String>,
}
impl DeleteJourneyOutputBuilder {
    /// <p>Provides information about the status, configuration, and other settings for a journey.</p>
    /// This field is required.
    pub fn journey_response(mut self, input: crate::types::JourneyResponse) -> Self {
        self.journey_response = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides information about the status, configuration, and other settings for a journey.</p>
    pub fn set_journey_response(mut self, input: ::std::option::Option<crate::types::JourneyResponse>) -> Self {
        self.journey_response = input;
        self
    }
    /// <p>Provides information about the status, configuration, and other settings for a journey.</p>
    pub fn get_journey_response(&self) -> &::std::option::Option<crate::types::JourneyResponse> {
        &self.journey_response
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteJourneyOutput`](crate::operation::delete_journey::DeleteJourneyOutput).
    pub fn build(self) -> crate::operation::delete_journey::DeleteJourneyOutput {
        crate::operation::delete_journey::DeleteJourneyOutput {
            journey_response: self.journey_response,
            _request_id: self._request_id,
        }
    }
}
