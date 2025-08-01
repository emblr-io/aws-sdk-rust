// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeCertificateAuthorityAuditReportOutput {
    /// <p>Specifies whether report creation is in progress, has succeeded, or has failed.</p>
    pub audit_report_status: ::std::option::Option<crate::types::AuditReportStatus>,
    /// <p>Name of the S3 bucket that contains the report.</p>
    pub s3_bucket_name: ::std::option::Option<::std::string::String>,
    /// <p>S3 <b>key</b> that uniquely identifies the report file in your S3 bucket.</p>
    pub s3_key: ::std::option::Option<::std::string::String>,
    /// <p>The date and time at which the report was created.</p>
    pub created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl DescribeCertificateAuthorityAuditReportOutput {
    /// <p>Specifies whether report creation is in progress, has succeeded, or has failed.</p>
    pub fn audit_report_status(&self) -> ::std::option::Option<&crate::types::AuditReportStatus> {
        self.audit_report_status.as_ref()
    }
    /// <p>Name of the S3 bucket that contains the report.</p>
    pub fn s3_bucket_name(&self) -> ::std::option::Option<&str> {
        self.s3_bucket_name.as_deref()
    }
    /// <p>S3 <b>key</b> that uniquely identifies the report file in your S3 bucket.</p>
    pub fn s3_key(&self) -> ::std::option::Option<&str> {
        self.s3_key.as_deref()
    }
    /// <p>The date and time at which the report was created.</p>
    pub fn created_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_at.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeCertificateAuthorityAuditReportOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeCertificateAuthorityAuditReportOutput {
    /// Creates a new builder-style object to manufacture [`DescribeCertificateAuthorityAuditReportOutput`](crate::operation::describe_certificate_authority_audit_report::DescribeCertificateAuthorityAuditReportOutput).
    pub fn builder() -> crate::operation::describe_certificate_authority_audit_report::builders::DescribeCertificateAuthorityAuditReportOutputBuilder
    {
        crate::operation::describe_certificate_authority_audit_report::builders::DescribeCertificateAuthorityAuditReportOutputBuilder::default()
    }
}

/// A builder for [`DescribeCertificateAuthorityAuditReportOutput`](crate::operation::describe_certificate_authority_audit_report::DescribeCertificateAuthorityAuditReportOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeCertificateAuthorityAuditReportOutputBuilder {
    pub(crate) audit_report_status: ::std::option::Option<crate::types::AuditReportStatus>,
    pub(crate) s3_bucket_name: ::std::option::Option<::std::string::String>,
    pub(crate) s3_key: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl DescribeCertificateAuthorityAuditReportOutputBuilder {
    /// <p>Specifies whether report creation is in progress, has succeeded, or has failed.</p>
    pub fn audit_report_status(mut self, input: crate::types::AuditReportStatus) -> Self {
        self.audit_report_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether report creation is in progress, has succeeded, or has failed.</p>
    pub fn set_audit_report_status(mut self, input: ::std::option::Option<crate::types::AuditReportStatus>) -> Self {
        self.audit_report_status = input;
        self
    }
    /// <p>Specifies whether report creation is in progress, has succeeded, or has failed.</p>
    pub fn get_audit_report_status(&self) -> &::std::option::Option<crate::types::AuditReportStatus> {
        &self.audit_report_status
    }
    /// <p>Name of the S3 bucket that contains the report.</p>
    pub fn s3_bucket_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_bucket_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of the S3 bucket that contains the report.</p>
    pub fn set_s3_bucket_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_bucket_name = input;
        self
    }
    /// <p>Name of the S3 bucket that contains the report.</p>
    pub fn get_s3_bucket_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_bucket_name
    }
    /// <p>S3 <b>key</b> that uniquely identifies the report file in your S3 bucket.</p>
    pub fn s3_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>S3 <b>key</b> that uniquely identifies the report file in your S3 bucket.</p>
    pub fn set_s3_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_key = input;
        self
    }
    /// <p>S3 <b>key</b> that uniquely identifies the report file in your S3 bucket.</p>
    pub fn get_s3_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_key
    }
    /// <p>The date and time at which the report was created.</p>
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time at which the report was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The date and time at which the report was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeCertificateAuthorityAuditReportOutput`](crate::operation::describe_certificate_authority_audit_report::DescribeCertificateAuthorityAuditReportOutput).
    pub fn build(self) -> crate::operation::describe_certificate_authority_audit_report::DescribeCertificateAuthorityAuditReportOutput {
        crate::operation::describe_certificate_authority_audit_report::DescribeCertificateAuthorityAuditReportOutput {
            audit_report_status: self.audit_report_status,
            s3_bucket_name: self.s3_bucket_name,
            s3_key: self.s3_key,
            created_at: self.created_at,
            _request_id: self._request_id,
        }
    }
}
