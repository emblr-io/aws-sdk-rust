// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A complex type that contains <code>HeaderName</code> and <code>HeaderValue</code> elements, if any, for this distribution.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct OriginCustomHeader {
    /// <p>The name of a header that you want CloudFront to send to your origin. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/forward-custom-headers.html">Adding Custom Headers to Origin Requests</a> in the <i> Amazon CloudFront Developer Guide</i>.</p>
    pub header_name: ::std::string::String,
    /// <p>The value for the header that you specified in the <code>HeaderName</code> field.</p>
    pub header_value: ::std::string::String,
}
impl OriginCustomHeader {
    /// <p>The name of a header that you want CloudFront to send to your origin. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/forward-custom-headers.html">Adding Custom Headers to Origin Requests</a> in the <i> Amazon CloudFront Developer Guide</i>.</p>
    pub fn header_name(&self) -> &str {
        use std::ops::Deref;
        self.header_name.deref()
    }
    /// <p>The value for the header that you specified in the <code>HeaderName</code> field.</p>
    pub fn header_value(&self) -> &str {
        use std::ops::Deref;
        self.header_value.deref()
    }
}
impl ::std::fmt::Debug for OriginCustomHeader {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("OriginCustomHeader");
        formatter.field("header_name", &self.header_name);
        formatter.field("header_value", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl OriginCustomHeader {
    /// Creates a new builder-style object to manufacture [`OriginCustomHeader`](crate::types::OriginCustomHeader).
    pub fn builder() -> crate::types::builders::OriginCustomHeaderBuilder {
        crate::types::builders::OriginCustomHeaderBuilder::default()
    }
}

/// A builder for [`OriginCustomHeader`](crate::types::OriginCustomHeader).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct OriginCustomHeaderBuilder {
    pub(crate) header_name: ::std::option::Option<::std::string::String>,
    pub(crate) header_value: ::std::option::Option<::std::string::String>,
}
impl OriginCustomHeaderBuilder {
    /// <p>The name of a header that you want CloudFront to send to your origin. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/forward-custom-headers.html">Adding Custom Headers to Origin Requests</a> in the <i> Amazon CloudFront Developer Guide</i>.</p>
    /// This field is required.
    pub fn header_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.header_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of a header that you want CloudFront to send to your origin. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/forward-custom-headers.html">Adding Custom Headers to Origin Requests</a> in the <i> Amazon CloudFront Developer Guide</i>.</p>
    pub fn set_header_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.header_name = input;
        self
    }
    /// <p>The name of a header that you want CloudFront to send to your origin. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/forward-custom-headers.html">Adding Custom Headers to Origin Requests</a> in the <i> Amazon CloudFront Developer Guide</i>.</p>
    pub fn get_header_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.header_name
    }
    /// <p>The value for the header that you specified in the <code>HeaderName</code> field.</p>
    /// This field is required.
    pub fn header_value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.header_value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value for the header that you specified in the <code>HeaderName</code> field.</p>
    pub fn set_header_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.header_value = input;
        self
    }
    /// <p>The value for the header that you specified in the <code>HeaderName</code> field.</p>
    pub fn get_header_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.header_value
    }
    /// Consumes the builder and constructs a [`OriginCustomHeader`](crate::types::OriginCustomHeader).
    /// This method will fail if any of the following fields are not set:
    /// - [`header_name`](crate::types::builders::OriginCustomHeaderBuilder::header_name)
    /// - [`header_value`](crate::types::builders::OriginCustomHeaderBuilder::header_value)
    pub fn build(self) -> ::std::result::Result<crate::types::OriginCustomHeader, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::OriginCustomHeader {
            header_name: self.header_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "header_name",
                    "header_name was not specified but it is required when building OriginCustomHeader",
                )
            })?,
            header_value: self.header_value.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "header_value",
                    "header_value was not specified but it is required when building OriginCustomHeader",
                )
            })?,
        })
    }
}
impl ::std::fmt::Debug for OriginCustomHeaderBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("OriginCustomHeaderBuilder");
        formatter.field("header_name", &self.header_name);
        formatter.field("header_value", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
