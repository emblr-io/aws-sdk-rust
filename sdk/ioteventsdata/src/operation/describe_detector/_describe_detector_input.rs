// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeDetectorInput {
    /// <p>The name of the detector model whose detectors (instances) you want information about.</p>
    pub detector_model_name: ::std::option::Option<::std::string::String>,
    /// <p>A filter used to limit results to detectors (instances) created because of the given key ID.</p>
    pub key_value: ::std::option::Option<::std::string::String>,
}
impl DescribeDetectorInput {
    /// <p>The name of the detector model whose detectors (instances) you want information about.</p>
    pub fn detector_model_name(&self) -> ::std::option::Option<&str> {
        self.detector_model_name.as_deref()
    }
    /// <p>A filter used to limit results to detectors (instances) created because of the given key ID.</p>
    pub fn key_value(&self) -> ::std::option::Option<&str> {
        self.key_value.as_deref()
    }
}
impl DescribeDetectorInput {
    /// Creates a new builder-style object to manufacture [`DescribeDetectorInput`](crate::operation::describe_detector::DescribeDetectorInput).
    pub fn builder() -> crate::operation::describe_detector::builders::DescribeDetectorInputBuilder {
        crate::operation::describe_detector::builders::DescribeDetectorInputBuilder::default()
    }
}

/// A builder for [`DescribeDetectorInput`](crate::operation::describe_detector::DescribeDetectorInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeDetectorInputBuilder {
    pub(crate) detector_model_name: ::std::option::Option<::std::string::String>,
    pub(crate) key_value: ::std::option::Option<::std::string::String>,
}
impl DescribeDetectorInputBuilder {
    /// <p>The name of the detector model whose detectors (instances) you want information about.</p>
    /// This field is required.
    pub fn detector_model_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.detector_model_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the detector model whose detectors (instances) you want information about.</p>
    pub fn set_detector_model_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.detector_model_name = input;
        self
    }
    /// <p>The name of the detector model whose detectors (instances) you want information about.</p>
    pub fn get_detector_model_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.detector_model_name
    }
    /// <p>A filter used to limit results to detectors (instances) created because of the given key ID.</p>
    pub fn key_value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key_value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A filter used to limit results to detectors (instances) created because of the given key ID.</p>
    pub fn set_key_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key_value = input;
        self
    }
    /// <p>A filter used to limit results to detectors (instances) created because of the given key ID.</p>
    pub fn get_key_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.key_value
    }
    /// Consumes the builder and constructs a [`DescribeDetectorInput`](crate::operation::describe_detector::DescribeDetectorInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_detector::DescribeDetectorInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::describe_detector::DescribeDetectorInput {
            detector_model_name: self.detector_model_name,
            key_value: self.key_value,
        })
    }
}
