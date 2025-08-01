// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RequestCertificateOutput {
    /// <p>String that contains the ARN of the issued certificate. This must be of the form:</p>
    /// <p><code>arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012</code></p>
    pub certificate_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl RequestCertificateOutput {
    /// <p>String that contains the ARN of the issued certificate. This must be of the form:</p>
    /// <p><code>arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012</code></p>
    pub fn certificate_arn(&self) -> ::std::option::Option<&str> {
        self.certificate_arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for RequestCertificateOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl RequestCertificateOutput {
    /// Creates a new builder-style object to manufacture [`RequestCertificateOutput`](crate::operation::request_certificate::RequestCertificateOutput).
    pub fn builder() -> crate::operation::request_certificate::builders::RequestCertificateOutputBuilder {
        crate::operation::request_certificate::builders::RequestCertificateOutputBuilder::default()
    }
}

/// A builder for [`RequestCertificateOutput`](crate::operation::request_certificate::RequestCertificateOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RequestCertificateOutputBuilder {
    pub(crate) certificate_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl RequestCertificateOutputBuilder {
    /// <p>String that contains the ARN of the issued certificate. This must be of the form:</p>
    /// <p><code>arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012</code></p>
    pub fn certificate_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.certificate_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>String that contains the ARN of the issued certificate. This must be of the form:</p>
    /// <p><code>arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012</code></p>
    pub fn set_certificate_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.certificate_arn = input;
        self
    }
    /// <p>String that contains the ARN of the issued certificate. This must be of the form:</p>
    /// <p><code>arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012</code></p>
    pub fn get_certificate_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.certificate_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`RequestCertificateOutput`](crate::operation::request_certificate::RequestCertificateOutput).
    pub fn build(self) -> crate::operation::request_certificate::RequestCertificateOutput {
        crate::operation::request_certificate::RequestCertificateOutput {
            certificate_arn: self.certificate_arn,
            _request_id: self._request_id,
        }
    }
}
