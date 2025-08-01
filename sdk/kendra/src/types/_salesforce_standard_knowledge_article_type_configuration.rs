// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides the configuration information for standard Salesforce knowledge articles.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SalesforceStandardKnowledgeArticleTypeConfiguration {
    /// <p>The name of the field that contains the document data to index.</p>
    pub document_data_field_name: ::std::string::String,
    /// <p>The name of the field that contains the document title.</p>
    pub document_title_field_name: ::std::option::Option<::std::string::String>,
    /// <p>Maps attributes or field names of the knowledge article to Amazon Kendra index field names. To create custom fields, use the <code>UpdateIndex</code> API before you map to Salesforce fields. For more information, see <a href="https://docs.aws.amazon.com/kendra/latest/dg/field-mapping.html">Mapping data source fields</a>. The Salesforce data source field names must exist in your Salesforce custom metadata.</p>
    pub field_mappings: ::std::option::Option<::std::vec::Vec<crate::types::DataSourceToIndexFieldMapping>>,
}
impl SalesforceStandardKnowledgeArticleTypeConfiguration {
    /// <p>The name of the field that contains the document data to index.</p>
    pub fn document_data_field_name(&self) -> &str {
        use std::ops::Deref;
        self.document_data_field_name.deref()
    }
    /// <p>The name of the field that contains the document title.</p>
    pub fn document_title_field_name(&self) -> ::std::option::Option<&str> {
        self.document_title_field_name.as_deref()
    }
    /// <p>Maps attributes or field names of the knowledge article to Amazon Kendra index field names. To create custom fields, use the <code>UpdateIndex</code> API before you map to Salesforce fields. For more information, see <a href="https://docs.aws.amazon.com/kendra/latest/dg/field-mapping.html">Mapping data source fields</a>. The Salesforce data source field names must exist in your Salesforce custom metadata.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.field_mappings.is_none()`.
    pub fn field_mappings(&self) -> &[crate::types::DataSourceToIndexFieldMapping] {
        self.field_mappings.as_deref().unwrap_or_default()
    }
}
impl SalesforceStandardKnowledgeArticleTypeConfiguration {
    /// Creates a new builder-style object to manufacture [`SalesforceStandardKnowledgeArticleTypeConfiguration`](crate::types::SalesforceStandardKnowledgeArticleTypeConfiguration).
    pub fn builder() -> crate::types::builders::SalesforceStandardKnowledgeArticleTypeConfigurationBuilder {
        crate::types::builders::SalesforceStandardKnowledgeArticleTypeConfigurationBuilder::default()
    }
}

/// A builder for [`SalesforceStandardKnowledgeArticleTypeConfiguration`](crate::types::SalesforceStandardKnowledgeArticleTypeConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SalesforceStandardKnowledgeArticleTypeConfigurationBuilder {
    pub(crate) document_data_field_name: ::std::option::Option<::std::string::String>,
    pub(crate) document_title_field_name: ::std::option::Option<::std::string::String>,
    pub(crate) field_mappings: ::std::option::Option<::std::vec::Vec<crate::types::DataSourceToIndexFieldMapping>>,
}
impl SalesforceStandardKnowledgeArticleTypeConfigurationBuilder {
    /// <p>The name of the field that contains the document data to index.</p>
    /// This field is required.
    pub fn document_data_field_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.document_data_field_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the field that contains the document data to index.</p>
    pub fn set_document_data_field_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.document_data_field_name = input;
        self
    }
    /// <p>The name of the field that contains the document data to index.</p>
    pub fn get_document_data_field_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.document_data_field_name
    }
    /// <p>The name of the field that contains the document title.</p>
    pub fn document_title_field_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.document_title_field_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the field that contains the document title.</p>
    pub fn set_document_title_field_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.document_title_field_name = input;
        self
    }
    /// <p>The name of the field that contains the document title.</p>
    pub fn get_document_title_field_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.document_title_field_name
    }
    /// Appends an item to `field_mappings`.
    ///
    /// To override the contents of this collection use [`set_field_mappings`](Self::set_field_mappings).
    ///
    /// <p>Maps attributes or field names of the knowledge article to Amazon Kendra index field names. To create custom fields, use the <code>UpdateIndex</code> API before you map to Salesforce fields. For more information, see <a href="https://docs.aws.amazon.com/kendra/latest/dg/field-mapping.html">Mapping data source fields</a>. The Salesforce data source field names must exist in your Salesforce custom metadata.</p>
    pub fn field_mappings(mut self, input: crate::types::DataSourceToIndexFieldMapping) -> Self {
        let mut v = self.field_mappings.unwrap_or_default();
        v.push(input);
        self.field_mappings = ::std::option::Option::Some(v);
        self
    }
    /// <p>Maps attributes or field names of the knowledge article to Amazon Kendra index field names. To create custom fields, use the <code>UpdateIndex</code> API before you map to Salesforce fields. For more information, see <a href="https://docs.aws.amazon.com/kendra/latest/dg/field-mapping.html">Mapping data source fields</a>. The Salesforce data source field names must exist in your Salesforce custom metadata.</p>
    pub fn set_field_mappings(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DataSourceToIndexFieldMapping>>) -> Self {
        self.field_mappings = input;
        self
    }
    /// <p>Maps attributes or field names of the knowledge article to Amazon Kendra index field names. To create custom fields, use the <code>UpdateIndex</code> API before you map to Salesforce fields. For more information, see <a href="https://docs.aws.amazon.com/kendra/latest/dg/field-mapping.html">Mapping data source fields</a>. The Salesforce data source field names must exist in your Salesforce custom metadata.</p>
    pub fn get_field_mappings(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DataSourceToIndexFieldMapping>> {
        &self.field_mappings
    }
    /// Consumes the builder and constructs a [`SalesforceStandardKnowledgeArticleTypeConfiguration`](crate::types::SalesforceStandardKnowledgeArticleTypeConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`document_data_field_name`](crate::types::builders::SalesforceStandardKnowledgeArticleTypeConfigurationBuilder::document_data_field_name)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::SalesforceStandardKnowledgeArticleTypeConfiguration, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::types::SalesforceStandardKnowledgeArticleTypeConfiguration {
            document_data_field_name: self.document_data_field_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "document_data_field_name",
                    "document_data_field_name was not specified but it is required when building SalesforceStandardKnowledgeArticleTypeConfiguration",
                )
            })?,
            document_title_field_name: self.document_title_field_name,
            field_mappings: self.field_mappings,
        })
    }
}
