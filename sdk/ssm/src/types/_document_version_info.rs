// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Version information about the document.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DocumentVersionInfo {
    /// <p>The document name.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The friendly name of the SSM document. This value can differ for each version of the document. If you want to update this value, see <code>UpdateDocument</code>.</p>
    pub display_name: ::std::option::Option<::std::string::String>,
    /// <p>The document version.</p>
    pub document_version: ::std::option::Option<::std::string::String>,
    /// <p>The version of the artifact associated with the document. For example, 12.6. This value is unique across all versions of a document, and can't be changed.</p>
    pub version_name: ::std::option::Option<::std::string::String>,
    /// <p>The date the document was created.</p>
    pub created_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>An identifier for the default version of the document.</p>
    pub is_default_version: bool,
    /// <p>The document format, either JSON or YAML.</p>
    pub document_format: ::std::option::Option<crate::types::DocumentFormat>,
    /// <p>The status of the SSM document, such as <code>Creating</code>, <code>Active</code>, <code>Failed</code>, and <code>Deleting</code>.</p>
    pub status: ::std::option::Option<crate::types::DocumentStatus>,
    /// <p>A message returned by Amazon Web Services Systems Manager that explains the <code>Status</code> value. For example, a <code>Failed</code> status might be explained by the <code>StatusInformation</code> message, "The specified S3 bucket doesn't exist. Verify that the URL of the S3 bucket is correct."</p>
    pub status_information: ::std::option::Option<::std::string::String>,
    /// <p>The current status of the approval review for the latest version of the document.</p>
    pub review_status: ::std::option::Option<crate::types::ReviewStatus>,
}
impl DocumentVersionInfo {
    /// <p>The document name.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The friendly name of the SSM document. This value can differ for each version of the document. If you want to update this value, see <code>UpdateDocument</code>.</p>
    pub fn display_name(&self) -> ::std::option::Option<&str> {
        self.display_name.as_deref()
    }
    /// <p>The document version.</p>
    pub fn document_version(&self) -> ::std::option::Option<&str> {
        self.document_version.as_deref()
    }
    /// <p>The version of the artifact associated with the document. For example, 12.6. This value is unique across all versions of a document, and can't be changed.</p>
    pub fn version_name(&self) -> ::std::option::Option<&str> {
        self.version_name.as_deref()
    }
    /// <p>The date the document was created.</p>
    pub fn created_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_date.as_ref()
    }
    /// <p>An identifier for the default version of the document.</p>
    pub fn is_default_version(&self) -> bool {
        self.is_default_version
    }
    /// <p>The document format, either JSON or YAML.</p>
    pub fn document_format(&self) -> ::std::option::Option<&crate::types::DocumentFormat> {
        self.document_format.as_ref()
    }
    /// <p>The status of the SSM document, such as <code>Creating</code>, <code>Active</code>, <code>Failed</code>, and <code>Deleting</code>.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::DocumentStatus> {
        self.status.as_ref()
    }
    /// <p>A message returned by Amazon Web Services Systems Manager that explains the <code>Status</code> value. For example, a <code>Failed</code> status might be explained by the <code>StatusInformation</code> message, "The specified S3 bucket doesn't exist. Verify that the URL of the S3 bucket is correct."</p>
    pub fn status_information(&self) -> ::std::option::Option<&str> {
        self.status_information.as_deref()
    }
    /// <p>The current status of the approval review for the latest version of the document.</p>
    pub fn review_status(&self) -> ::std::option::Option<&crate::types::ReviewStatus> {
        self.review_status.as_ref()
    }
}
impl DocumentVersionInfo {
    /// Creates a new builder-style object to manufacture [`DocumentVersionInfo`](crate::types::DocumentVersionInfo).
    pub fn builder() -> crate::types::builders::DocumentVersionInfoBuilder {
        crate::types::builders::DocumentVersionInfoBuilder::default()
    }
}

/// A builder for [`DocumentVersionInfo`](crate::types::DocumentVersionInfo).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DocumentVersionInfoBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) display_name: ::std::option::Option<::std::string::String>,
    pub(crate) document_version: ::std::option::Option<::std::string::String>,
    pub(crate) version_name: ::std::option::Option<::std::string::String>,
    pub(crate) created_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) is_default_version: ::std::option::Option<bool>,
    pub(crate) document_format: ::std::option::Option<crate::types::DocumentFormat>,
    pub(crate) status: ::std::option::Option<crate::types::DocumentStatus>,
    pub(crate) status_information: ::std::option::Option<::std::string::String>,
    pub(crate) review_status: ::std::option::Option<crate::types::ReviewStatus>,
}
impl DocumentVersionInfoBuilder {
    /// <p>The document name.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The document name.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The document name.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The friendly name of the SSM document. This value can differ for each version of the document. If you want to update this value, see <code>UpdateDocument</code>.</p>
    pub fn display_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.display_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The friendly name of the SSM document. This value can differ for each version of the document. If you want to update this value, see <code>UpdateDocument</code>.</p>
    pub fn set_display_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.display_name = input;
        self
    }
    /// <p>The friendly name of the SSM document. This value can differ for each version of the document. If you want to update this value, see <code>UpdateDocument</code>.</p>
    pub fn get_display_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.display_name
    }
    /// <p>The document version.</p>
    pub fn document_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.document_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The document version.</p>
    pub fn set_document_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.document_version = input;
        self
    }
    /// <p>The document version.</p>
    pub fn get_document_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.document_version
    }
    /// <p>The version of the artifact associated with the document. For example, 12.6. This value is unique across all versions of a document, and can't be changed.</p>
    pub fn version_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the artifact associated with the document. For example, 12.6. This value is unique across all versions of a document, and can't be changed.</p>
    pub fn set_version_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version_name = input;
        self
    }
    /// <p>The version of the artifact associated with the document. For example, 12.6. This value is unique across all versions of a document, and can't be changed.</p>
    pub fn get_version_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.version_name
    }
    /// <p>The date the document was created.</p>
    pub fn created_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date the document was created.</p>
    pub fn set_created_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_date = input;
        self
    }
    /// <p>The date the document was created.</p>
    pub fn get_created_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_date
    }
    /// <p>An identifier for the default version of the document.</p>
    pub fn is_default_version(mut self, input: bool) -> Self {
        self.is_default_version = ::std::option::Option::Some(input);
        self
    }
    /// <p>An identifier for the default version of the document.</p>
    pub fn set_is_default_version(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_default_version = input;
        self
    }
    /// <p>An identifier for the default version of the document.</p>
    pub fn get_is_default_version(&self) -> &::std::option::Option<bool> {
        &self.is_default_version
    }
    /// <p>The document format, either JSON or YAML.</p>
    pub fn document_format(mut self, input: crate::types::DocumentFormat) -> Self {
        self.document_format = ::std::option::Option::Some(input);
        self
    }
    /// <p>The document format, either JSON or YAML.</p>
    pub fn set_document_format(mut self, input: ::std::option::Option<crate::types::DocumentFormat>) -> Self {
        self.document_format = input;
        self
    }
    /// <p>The document format, either JSON or YAML.</p>
    pub fn get_document_format(&self) -> &::std::option::Option<crate::types::DocumentFormat> {
        &self.document_format
    }
    /// <p>The status of the SSM document, such as <code>Creating</code>, <code>Active</code>, <code>Failed</code>, and <code>Deleting</code>.</p>
    pub fn status(mut self, input: crate::types::DocumentStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the SSM document, such as <code>Creating</code>, <code>Active</code>, <code>Failed</code>, and <code>Deleting</code>.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::DocumentStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the SSM document, such as <code>Creating</code>, <code>Active</code>, <code>Failed</code>, and <code>Deleting</code>.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::DocumentStatus> {
        &self.status
    }
    /// <p>A message returned by Amazon Web Services Systems Manager that explains the <code>Status</code> value. For example, a <code>Failed</code> status might be explained by the <code>StatusInformation</code> message, "The specified S3 bucket doesn't exist. Verify that the URL of the S3 bucket is correct."</p>
    pub fn status_information(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status_information = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A message returned by Amazon Web Services Systems Manager that explains the <code>Status</code> value. For example, a <code>Failed</code> status might be explained by the <code>StatusInformation</code> message, "The specified S3 bucket doesn't exist. Verify that the URL of the S3 bucket is correct."</p>
    pub fn set_status_information(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status_information = input;
        self
    }
    /// <p>A message returned by Amazon Web Services Systems Manager that explains the <code>Status</code> value. For example, a <code>Failed</code> status might be explained by the <code>StatusInformation</code> message, "The specified S3 bucket doesn't exist. Verify that the URL of the S3 bucket is correct."</p>
    pub fn get_status_information(&self) -> &::std::option::Option<::std::string::String> {
        &self.status_information
    }
    /// <p>The current status of the approval review for the latest version of the document.</p>
    pub fn review_status(mut self, input: crate::types::ReviewStatus) -> Self {
        self.review_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current status of the approval review for the latest version of the document.</p>
    pub fn set_review_status(mut self, input: ::std::option::Option<crate::types::ReviewStatus>) -> Self {
        self.review_status = input;
        self
    }
    /// <p>The current status of the approval review for the latest version of the document.</p>
    pub fn get_review_status(&self) -> &::std::option::Option<crate::types::ReviewStatus> {
        &self.review_status
    }
    /// Consumes the builder and constructs a [`DocumentVersionInfo`](crate::types::DocumentVersionInfo).
    pub fn build(self) -> crate::types::DocumentVersionInfo {
        crate::types::DocumentVersionInfo {
            name: self.name,
            display_name: self.display_name,
            document_version: self.document_version,
            version_name: self.version_name,
            created_date: self.created_date,
            is_default_version: self.is_default_version.unwrap_or_default(),
            document_format: self.document_format,
            status: self.status,
            status_information: self.status_information,
            review_status: self.review_status,
        }
    }
}
