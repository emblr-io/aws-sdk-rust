// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeDetectorOutput {
    /// <p>Information about the detector (instance).</p>
    pub detector: ::std::option::Option<crate::types::Detector>,
    _request_id: Option<String>,
}
impl DescribeDetectorOutput {
    /// <p>Information about the detector (instance).</p>
    pub fn detector(&self) -> ::std::option::Option<&crate::types::Detector> {
        self.detector.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeDetectorOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeDetectorOutput {
    /// Creates a new builder-style object to manufacture [`DescribeDetectorOutput`](crate::operation::describe_detector::DescribeDetectorOutput).
    pub fn builder() -> crate::operation::describe_detector::builders::DescribeDetectorOutputBuilder {
        crate::operation::describe_detector::builders::DescribeDetectorOutputBuilder::default()
    }
}

/// A builder for [`DescribeDetectorOutput`](crate::operation::describe_detector::DescribeDetectorOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeDetectorOutputBuilder {
    pub(crate) detector: ::std::option::Option<crate::types::Detector>,
    _request_id: Option<String>,
}
impl DescribeDetectorOutputBuilder {
    /// <p>Information about the detector (instance).</p>
    pub fn detector(mut self, input: crate::types::Detector) -> Self {
        self.detector = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the detector (instance).</p>
    pub fn set_detector(mut self, input: ::std::option::Option<crate::types::Detector>) -> Self {
        self.detector = input;
        self
    }
    /// <p>Information about the detector (instance).</p>
    pub fn get_detector(&self) -> &::std::option::Option<crate::types::Detector> {
        &self.detector
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeDetectorOutput`](crate::operation::describe_detector::DescribeDetectorOutput).
    pub fn build(self) -> crate::operation::describe_detector::DescribeDetectorOutput {
        crate::operation::describe_detector::DescribeDetectorOutput {
            detector: self.detector,
            _request_id: self._request_id,
        }
    }
}
