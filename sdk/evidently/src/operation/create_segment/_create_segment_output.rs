// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateSegmentOutput {
    /// <p>A structure that contains the complete information about the segment that was just created.</p>
    pub segment: ::std::option::Option<crate::types::Segment>,
    _request_id: Option<String>,
}
impl CreateSegmentOutput {
    /// <p>A structure that contains the complete information about the segment that was just created.</p>
    pub fn segment(&self) -> ::std::option::Option<&crate::types::Segment> {
        self.segment.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateSegmentOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateSegmentOutput {
    /// Creates a new builder-style object to manufacture [`CreateSegmentOutput`](crate::operation::create_segment::CreateSegmentOutput).
    pub fn builder() -> crate::operation::create_segment::builders::CreateSegmentOutputBuilder {
        crate::operation::create_segment::builders::CreateSegmentOutputBuilder::default()
    }
}

/// A builder for [`CreateSegmentOutput`](crate::operation::create_segment::CreateSegmentOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateSegmentOutputBuilder {
    pub(crate) segment: ::std::option::Option<crate::types::Segment>,
    _request_id: Option<String>,
}
impl CreateSegmentOutputBuilder {
    /// <p>A structure that contains the complete information about the segment that was just created.</p>
    /// This field is required.
    pub fn segment(mut self, input: crate::types::Segment) -> Self {
        self.segment = ::std::option::Option::Some(input);
        self
    }
    /// <p>A structure that contains the complete information about the segment that was just created.</p>
    pub fn set_segment(mut self, input: ::std::option::Option<crate::types::Segment>) -> Self {
        self.segment = input;
        self
    }
    /// <p>A structure that contains the complete information about the segment that was just created.</p>
    pub fn get_segment(&self) -> &::std::option::Option<crate::types::Segment> {
        &self.segment
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateSegmentOutput`](crate::operation::create_segment::CreateSegmentOutput).
    pub fn build(self) -> crate::operation::create_segment::CreateSegmentOutput {
        crate::operation::create_segment::CreateSegmentOutput {
            segment: self.segment,
            _request_id: self._request_id,
        }
    }
}
