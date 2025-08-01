// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetSegmentsOutput {
    /// <p>Provides information about all the segments that are associated with an application.</p>
    pub segments_response: ::std::option::Option<crate::types::SegmentsResponse>,
    _request_id: Option<String>,
}
impl GetSegmentsOutput {
    /// <p>Provides information about all the segments that are associated with an application.</p>
    pub fn segments_response(&self) -> ::std::option::Option<&crate::types::SegmentsResponse> {
        self.segments_response.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetSegmentsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetSegmentsOutput {
    /// Creates a new builder-style object to manufacture [`GetSegmentsOutput`](crate::operation::get_segments::GetSegmentsOutput).
    pub fn builder() -> crate::operation::get_segments::builders::GetSegmentsOutputBuilder {
        crate::operation::get_segments::builders::GetSegmentsOutputBuilder::default()
    }
}

/// A builder for [`GetSegmentsOutput`](crate::operation::get_segments::GetSegmentsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetSegmentsOutputBuilder {
    pub(crate) segments_response: ::std::option::Option<crate::types::SegmentsResponse>,
    _request_id: Option<String>,
}
impl GetSegmentsOutputBuilder {
    /// <p>Provides information about all the segments that are associated with an application.</p>
    /// This field is required.
    pub fn segments_response(mut self, input: crate::types::SegmentsResponse) -> Self {
        self.segments_response = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides information about all the segments that are associated with an application.</p>
    pub fn set_segments_response(mut self, input: ::std::option::Option<crate::types::SegmentsResponse>) -> Self {
        self.segments_response = input;
        self
    }
    /// <p>Provides information about all the segments that are associated with an application.</p>
    pub fn get_segments_response(&self) -> &::std::option::Option<crate::types::SegmentsResponse> {
        &self.segments_response
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetSegmentsOutput`](crate::operation::get_segments::GetSegmentsOutput).
    pub fn build(self) -> crate::operation::get_segments::GetSegmentsOutput {
        crate::operation::get_segments::GetSegmentsOutput {
            segments_response: self.segments_response,
            _request_id: self._request_id,
        }
    }
}
