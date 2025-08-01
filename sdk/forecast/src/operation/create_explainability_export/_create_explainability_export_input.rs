// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateExplainabilityExportInput {
    /// <p>A unique name for the Explainability export.</p>
    pub explainability_export_name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the Explainability to export.</p>
    pub explainability_arn: ::std::option::Option<::std::string::String>,
    /// <p>The destination for an export job. Provide an S3 path, an Identity and Access Management (IAM) role that allows Amazon Forecast to access the location, and an Key Management Service (KMS) key (optional).</p>
    pub destination: ::std::option::Option<crate::types::DataDestination>,
    /// <p>Optional metadata to help you categorize and organize your resources. Each tag consists of a key and an optional value, both of which you define. Tag keys and values are case sensitive.</p>
    /// <p>The following restrictions apply to tags:</p>
    /// <ul>
    /// <li>
    /// <p>For each resource, each tag key must be unique and each tag key must have one value.</p></li>
    /// <li>
    /// <p>Maximum number of tags per resource: 50.</p></li>
    /// <li>
    /// <p>Maximum key length: 128 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>Maximum value length: 256 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>Accepted characters: all letters and numbers, spaces representable in UTF-8, and + - = . _ : / @. If your tagging schema is used across other services and resources, the character restrictions of those services also apply.</p></li>
    /// <li>
    /// <p>Key prefixes cannot include any upper or lowercase combination of <code>aws:</code> or <code>AWS:</code>. Values can have this prefix. If a tag value has <code>aws</code> as its prefix but the key does not, Forecast considers it to be a user tag and will count against the limit of 50 tags. Tags with only the key prefix of <code>aws</code> do not count against your tags per resource limit. You cannot edit or delete tag keys with this prefix.</p></li>
    /// </ul>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    /// <p>The format of the exported data, CSV or PARQUET.</p>
    pub format: ::std::option::Option<::std::string::String>,
}
impl CreateExplainabilityExportInput {
    /// <p>A unique name for the Explainability export.</p>
    pub fn explainability_export_name(&self) -> ::std::option::Option<&str> {
        self.explainability_export_name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the Explainability to export.</p>
    pub fn explainability_arn(&self) -> ::std::option::Option<&str> {
        self.explainability_arn.as_deref()
    }
    /// <p>The destination for an export job. Provide an S3 path, an Identity and Access Management (IAM) role that allows Amazon Forecast to access the location, and an Key Management Service (KMS) key (optional).</p>
    pub fn destination(&self) -> ::std::option::Option<&crate::types::DataDestination> {
        self.destination.as_ref()
    }
    /// <p>Optional metadata to help you categorize and organize your resources. Each tag consists of a key and an optional value, both of which you define. Tag keys and values are case sensitive.</p>
    /// <p>The following restrictions apply to tags:</p>
    /// <ul>
    /// <li>
    /// <p>For each resource, each tag key must be unique and each tag key must have one value.</p></li>
    /// <li>
    /// <p>Maximum number of tags per resource: 50.</p></li>
    /// <li>
    /// <p>Maximum key length: 128 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>Maximum value length: 256 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>Accepted characters: all letters and numbers, spaces representable in UTF-8, and + - = . _ : / @. If your tagging schema is used across other services and resources, the character restrictions of those services also apply.</p></li>
    /// <li>
    /// <p>Key prefixes cannot include any upper or lowercase combination of <code>aws:</code> or <code>AWS:</code>. Values can have this prefix. If a tag value has <code>aws</code> as its prefix but the key does not, Forecast considers it to be a user tag and will count against the limit of 50 tags. Tags with only the key prefix of <code>aws</code> do not count against your tags per resource limit. You cannot edit or delete tag keys with this prefix.</p></li>
    /// </ul>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
    /// <p>The format of the exported data, CSV or PARQUET.</p>
    pub fn format(&self) -> ::std::option::Option<&str> {
        self.format.as_deref()
    }
}
impl CreateExplainabilityExportInput {
    /// Creates a new builder-style object to manufacture [`CreateExplainabilityExportInput`](crate::operation::create_explainability_export::CreateExplainabilityExportInput).
    pub fn builder() -> crate::operation::create_explainability_export::builders::CreateExplainabilityExportInputBuilder {
        crate::operation::create_explainability_export::builders::CreateExplainabilityExportInputBuilder::default()
    }
}

/// A builder for [`CreateExplainabilityExportInput`](crate::operation::create_explainability_export::CreateExplainabilityExportInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateExplainabilityExportInputBuilder {
    pub(crate) explainability_export_name: ::std::option::Option<::std::string::String>,
    pub(crate) explainability_arn: ::std::option::Option<::std::string::String>,
    pub(crate) destination: ::std::option::Option<crate::types::DataDestination>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    pub(crate) format: ::std::option::Option<::std::string::String>,
}
impl CreateExplainabilityExportInputBuilder {
    /// <p>A unique name for the Explainability export.</p>
    /// This field is required.
    pub fn explainability_export_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.explainability_export_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique name for the Explainability export.</p>
    pub fn set_explainability_export_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.explainability_export_name = input;
        self
    }
    /// <p>A unique name for the Explainability export.</p>
    pub fn get_explainability_export_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.explainability_export_name
    }
    /// <p>The Amazon Resource Name (ARN) of the Explainability to export.</p>
    /// This field is required.
    pub fn explainability_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.explainability_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Explainability to export.</p>
    pub fn set_explainability_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.explainability_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Explainability to export.</p>
    pub fn get_explainability_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.explainability_arn
    }
    /// <p>The destination for an export job. Provide an S3 path, an Identity and Access Management (IAM) role that allows Amazon Forecast to access the location, and an Key Management Service (KMS) key (optional).</p>
    /// This field is required.
    pub fn destination(mut self, input: crate::types::DataDestination) -> Self {
        self.destination = ::std::option::Option::Some(input);
        self
    }
    /// <p>The destination for an export job. Provide an S3 path, an Identity and Access Management (IAM) role that allows Amazon Forecast to access the location, and an Key Management Service (KMS) key (optional).</p>
    pub fn set_destination(mut self, input: ::std::option::Option<crate::types::DataDestination>) -> Self {
        self.destination = input;
        self
    }
    /// <p>The destination for an export job. Provide an S3 path, an Identity and Access Management (IAM) role that allows Amazon Forecast to access the location, and an Key Management Service (KMS) key (optional).</p>
    pub fn get_destination(&self) -> &::std::option::Option<crate::types::DataDestination> {
        &self.destination
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Optional metadata to help you categorize and organize your resources. Each tag consists of a key and an optional value, both of which you define. Tag keys and values are case sensitive.</p>
    /// <p>The following restrictions apply to tags:</p>
    /// <ul>
    /// <li>
    /// <p>For each resource, each tag key must be unique and each tag key must have one value.</p></li>
    /// <li>
    /// <p>Maximum number of tags per resource: 50.</p></li>
    /// <li>
    /// <p>Maximum key length: 128 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>Maximum value length: 256 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>Accepted characters: all letters and numbers, spaces representable in UTF-8, and + - = . _ : / @. If your tagging schema is used across other services and resources, the character restrictions of those services also apply.</p></li>
    /// <li>
    /// <p>Key prefixes cannot include any upper or lowercase combination of <code>aws:</code> or <code>AWS:</code>. Values can have this prefix. If a tag value has <code>aws</code> as its prefix but the key does not, Forecast considers it to be a user tag and will count against the limit of 50 tags. Tags with only the key prefix of <code>aws</code> do not count against your tags per resource limit. You cannot edit or delete tag keys with this prefix.</p></li>
    /// </ul>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>Optional metadata to help you categorize and organize your resources. Each tag consists of a key and an optional value, both of which you define. Tag keys and values are case sensitive.</p>
    /// <p>The following restrictions apply to tags:</p>
    /// <ul>
    /// <li>
    /// <p>For each resource, each tag key must be unique and each tag key must have one value.</p></li>
    /// <li>
    /// <p>Maximum number of tags per resource: 50.</p></li>
    /// <li>
    /// <p>Maximum key length: 128 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>Maximum value length: 256 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>Accepted characters: all letters and numbers, spaces representable in UTF-8, and + - = . _ : / @. If your tagging schema is used across other services and resources, the character restrictions of those services also apply.</p></li>
    /// <li>
    /// <p>Key prefixes cannot include any upper or lowercase combination of <code>aws:</code> or <code>AWS:</code>. Values can have this prefix. If a tag value has <code>aws</code> as its prefix but the key does not, Forecast considers it to be a user tag and will count against the limit of 50 tags. Tags with only the key prefix of <code>aws</code> do not count against your tags per resource limit. You cannot edit or delete tag keys with this prefix.</p></li>
    /// </ul>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Optional metadata to help you categorize and organize your resources. Each tag consists of a key and an optional value, both of which you define. Tag keys and values are case sensitive.</p>
    /// <p>The following restrictions apply to tags:</p>
    /// <ul>
    /// <li>
    /// <p>For each resource, each tag key must be unique and each tag key must have one value.</p></li>
    /// <li>
    /// <p>Maximum number of tags per resource: 50.</p></li>
    /// <li>
    /// <p>Maximum key length: 128 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>Maximum value length: 256 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>Accepted characters: all letters and numbers, spaces representable in UTF-8, and + - = . _ : / @. If your tagging schema is used across other services and resources, the character restrictions of those services also apply.</p></li>
    /// <li>
    /// <p>Key prefixes cannot include any upper or lowercase combination of <code>aws:</code> or <code>AWS:</code>. Values can have this prefix. If a tag value has <code>aws</code> as its prefix but the key does not, Forecast considers it to be a user tag and will count against the limit of 50 tags. Tags with only the key prefix of <code>aws</code> do not count against your tags per resource limit. You cannot edit or delete tag keys with this prefix.</p></li>
    /// </ul>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// <p>The format of the exported data, CSV or PARQUET.</p>
    pub fn format(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.format = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The format of the exported data, CSV or PARQUET.</p>
    pub fn set_format(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.format = input;
        self
    }
    /// <p>The format of the exported data, CSV or PARQUET.</p>
    pub fn get_format(&self) -> &::std::option::Option<::std::string::String> {
        &self.format
    }
    /// Consumes the builder and constructs a [`CreateExplainabilityExportInput`](crate::operation::create_explainability_export::CreateExplainabilityExportInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_explainability_export::CreateExplainabilityExportInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_explainability_export::CreateExplainabilityExportInput {
            explainability_export_name: self.explainability_export_name,
            explainability_arn: self.explainability_arn,
            destination: self.destination,
            tags: self.tags,
            format: self.format,
        })
    }
}
