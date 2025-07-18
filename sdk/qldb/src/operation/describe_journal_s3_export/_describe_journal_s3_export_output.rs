// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeJournalS3ExportOutput {
    /// <p>Information about the journal export job returned by a <code>DescribeJournalS3Export</code> request.</p>
    pub export_description: ::std::option::Option<crate::types::JournalS3ExportDescription>,
    _request_id: Option<String>,
}
impl DescribeJournalS3ExportOutput {
    /// <p>Information about the journal export job returned by a <code>DescribeJournalS3Export</code> request.</p>
    pub fn export_description(&self) -> ::std::option::Option<&crate::types::JournalS3ExportDescription> {
        self.export_description.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeJournalS3ExportOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeJournalS3ExportOutput {
    /// Creates a new builder-style object to manufacture [`DescribeJournalS3ExportOutput`](crate::operation::describe_journal_s3_export::DescribeJournalS3ExportOutput).
    pub fn builder() -> crate::operation::describe_journal_s3_export::builders::DescribeJournalS3ExportOutputBuilder {
        crate::operation::describe_journal_s3_export::builders::DescribeJournalS3ExportOutputBuilder::default()
    }
}

/// A builder for [`DescribeJournalS3ExportOutput`](crate::operation::describe_journal_s3_export::DescribeJournalS3ExportOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeJournalS3ExportOutputBuilder {
    pub(crate) export_description: ::std::option::Option<crate::types::JournalS3ExportDescription>,
    _request_id: Option<String>,
}
impl DescribeJournalS3ExportOutputBuilder {
    /// <p>Information about the journal export job returned by a <code>DescribeJournalS3Export</code> request.</p>
    /// This field is required.
    pub fn export_description(mut self, input: crate::types::JournalS3ExportDescription) -> Self {
        self.export_description = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the journal export job returned by a <code>DescribeJournalS3Export</code> request.</p>
    pub fn set_export_description(mut self, input: ::std::option::Option<crate::types::JournalS3ExportDescription>) -> Self {
        self.export_description = input;
        self
    }
    /// <p>Information about the journal export job returned by a <code>DescribeJournalS3Export</code> request.</p>
    pub fn get_export_description(&self) -> &::std::option::Option<crate::types::JournalS3ExportDescription> {
        &self.export_description
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeJournalS3ExportOutput`](crate::operation::describe_journal_s3_export::DescribeJournalS3ExportOutput).
    pub fn build(self) -> crate::operation::describe_journal_s3_export::DescribeJournalS3ExportOutput {
        crate::operation::describe_journal_s3_export::DescribeJournalS3ExportOutput {
            export_description: self.export_description,
            _request_id: self._request_id,
        }
    }
}
