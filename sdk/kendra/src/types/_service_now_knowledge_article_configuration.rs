// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides the configuration information for crawling knowledge articles in the ServiceNow site.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ServiceNowKnowledgeArticleConfiguration {
    /// <p><code>TRUE</code> to index attachments to knowledge articles.</p>
    pub crawl_attachments: bool,
    /// <p>A list of regular expression patterns applied to include knowledge article attachments. Attachments that match the patterns are included in the index. Items that don't match the patterns are excluded from the index. If an item matches both an inclusion and exclusion pattern, the exclusion pattern takes precedence and the item isn't included in the index.</p>
    pub include_attachment_file_patterns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>A list of regular expression patterns applied to exclude certain knowledge article attachments. Attachments that match the patterns are excluded from the index. Items that don't match the patterns are included in the index. If an item matches both an inclusion and exclusion pattern, the exclusion pattern takes precedence and the item isn't included in the index.</p>
    pub exclude_attachment_file_patterns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The name of the ServiceNow field that is mapped to the index document contents field in the Amazon Kendra index.</p>
    pub document_data_field_name: ::std::string::String,
    /// <p>The name of the ServiceNow field that is mapped to the index document title field.</p>
    pub document_title_field_name: ::std::option::Option<::std::string::String>,
    /// <p>Maps attributes or field names of knoweldge articles to Amazon Kendra index field names. To create custom fields, use the <code>UpdateIndex</code> API before you map to ServiceNow fields. For more information, see <a href="https://docs.aws.amazon.com/kendra/latest/dg/field-mapping.html">Mapping data source fields</a>. The ServiceNow data source field names must exist in your ServiceNow custom metadata.</p>
    pub field_mappings: ::std::option::Option<::std::vec::Vec<crate::types::DataSourceToIndexFieldMapping>>,
    /// <p>A query that selects the knowledge articles to index. The query can return articles from multiple knowledge bases, and the knowledge bases can be public or private.</p>
    /// <p>The query string must be one generated by the ServiceNow console. For more information, see <a href="https://docs.aws.amazon.com/kendra/latest/dg/servicenow-query.html">Specifying documents to index with a query</a>.</p>
    pub filter_query: ::std::option::Option<::std::string::String>,
}
impl ServiceNowKnowledgeArticleConfiguration {
    /// <p><code>TRUE</code> to index attachments to knowledge articles.</p>
    pub fn crawl_attachments(&self) -> bool {
        self.crawl_attachments
    }
    /// <p>A list of regular expression patterns applied to include knowledge article attachments. Attachments that match the patterns are included in the index. Items that don't match the patterns are excluded from the index. If an item matches both an inclusion and exclusion pattern, the exclusion pattern takes precedence and the item isn't included in the index.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.include_attachment_file_patterns.is_none()`.
    pub fn include_attachment_file_patterns(&self) -> &[::std::string::String] {
        self.include_attachment_file_patterns.as_deref().unwrap_or_default()
    }
    /// <p>A list of regular expression patterns applied to exclude certain knowledge article attachments. Attachments that match the patterns are excluded from the index. Items that don't match the patterns are included in the index. If an item matches both an inclusion and exclusion pattern, the exclusion pattern takes precedence and the item isn't included in the index.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.exclude_attachment_file_patterns.is_none()`.
    pub fn exclude_attachment_file_patterns(&self) -> &[::std::string::String] {
        self.exclude_attachment_file_patterns.as_deref().unwrap_or_default()
    }
    /// <p>The name of the ServiceNow field that is mapped to the index document contents field in the Amazon Kendra index.</p>
    pub fn document_data_field_name(&self) -> &str {
        use std::ops::Deref;
        self.document_data_field_name.deref()
    }
    /// <p>The name of the ServiceNow field that is mapped to the index document title field.</p>
    pub fn document_title_field_name(&self) -> ::std::option::Option<&str> {
        self.document_title_field_name.as_deref()
    }
    /// <p>Maps attributes or field names of knoweldge articles to Amazon Kendra index field names. To create custom fields, use the <code>UpdateIndex</code> API before you map to ServiceNow fields. For more information, see <a href="https://docs.aws.amazon.com/kendra/latest/dg/field-mapping.html">Mapping data source fields</a>. The ServiceNow data source field names must exist in your ServiceNow custom metadata.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.field_mappings.is_none()`.
    pub fn field_mappings(&self) -> &[crate::types::DataSourceToIndexFieldMapping] {
        self.field_mappings.as_deref().unwrap_or_default()
    }
    /// <p>A query that selects the knowledge articles to index. The query can return articles from multiple knowledge bases, and the knowledge bases can be public or private.</p>
    /// <p>The query string must be one generated by the ServiceNow console. For more information, see <a href="https://docs.aws.amazon.com/kendra/latest/dg/servicenow-query.html">Specifying documents to index with a query</a>.</p>
    pub fn filter_query(&self) -> ::std::option::Option<&str> {
        self.filter_query.as_deref()
    }
}
impl ServiceNowKnowledgeArticleConfiguration {
    /// Creates a new builder-style object to manufacture [`ServiceNowKnowledgeArticleConfiguration`](crate::types::ServiceNowKnowledgeArticleConfiguration).
    pub fn builder() -> crate::types::builders::ServiceNowKnowledgeArticleConfigurationBuilder {
        crate::types::builders::ServiceNowKnowledgeArticleConfigurationBuilder::default()
    }
}

/// A builder for [`ServiceNowKnowledgeArticleConfiguration`](crate::types::ServiceNowKnowledgeArticleConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ServiceNowKnowledgeArticleConfigurationBuilder {
    pub(crate) crawl_attachments: ::std::option::Option<bool>,
    pub(crate) include_attachment_file_patterns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) exclude_attachment_file_patterns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) document_data_field_name: ::std::option::Option<::std::string::String>,
    pub(crate) document_title_field_name: ::std::option::Option<::std::string::String>,
    pub(crate) field_mappings: ::std::option::Option<::std::vec::Vec<crate::types::DataSourceToIndexFieldMapping>>,
    pub(crate) filter_query: ::std::option::Option<::std::string::String>,
}
impl ServiceNowKnowledgeArticleConfigurationBuilder {
    /// <p><code>TRUE</code> to index attachments to knowledge articles.</p>
    pub fn crawl_attachments(mut self, input: bool) -> Self {
        self.crawl_attachments = ::std::option::Option::Some(input);
        self
    }
    /// <p><code>TRUE</code> to index attachments to knowledge articles.</p>
    pub fn set_crawl_attachments(mut self, input: ::std::option::Option<bool>) -> Self {
        self.crawl_attachments = input;
        self
    }
    /// <p><code>TRUE</code> to index attachments to knowledge articles.</p>
    pub fn get_crawl_attachments(&self) -> &::std::option::Option<bool> {
        &self.crawl_attachments
    }
    /// Appends an item to `include_attachment_file_patterns`.
    ///
    /// To override the contents of this collection use [`set_include_attachment_file_patterns`](Self::set_include_attachment_file_patterns).
    ///
    /// <p>A list of regular expression patterns applied to include knowledge article attachments. Attachments that match the patterns are included in the index. Items that don't match the patterns are excluded from the index. If an item matches both an inclusion and exclusion pattern, the exclusion pattern takes precedence and the item isn't included in the index.</p>
    pub fn include_attachment_file_patterns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.include_attachment_file_patterns.unwrap_or_default();
        v.push(input.into());
        self.include_attachment_file_patterns = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of regular expression patterns applied to include knowledge article attachments. Attachments that match the patterns are included in the index. Items that don't match the patterns are excluded from the index. If an item matches both an inclusion and exclusion pattern, the exclusion pattern takes precedence and the item isn't included in the index.</p>
    pub fn set_include_attachment_file_patterns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.include_attachment_file_patterns = input;
        self
    }
    /// <p>A list of regular expression patterns applied to include knowledge article attachments. Attachments that match the patterns are included in the index. Items that don't match the patterns are excluded from the index. If an item matches both an inclusion and exclusion pattern, the exclusion pattern takes precedence and the item isn't included in the index.</p>
    pub fn get_include_attachment_file_patterns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.include_attachment_file_patterns
    }
    /// Appends an item to `exclude_attachment_file_patterns`.
    ///
    /// To override the contents of this collection use [`set_exclude_attachment_file_patterns`](Self::set_exclude_attachment_file_patterns).
    ///
    /// <p>A list of regular expression patterns applied to exclude certain knowledge article attachments. Attachments that match the patterns are excluded from the index. Items that don't match the patterns are included in the index. If an item matches both an inclusion and exclusion pattern, the exclusion pattern takes precedence and the item isn't included in the index.</p>
    pub fn exclude_attachment_file_patterns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.exclude_attachment_file_patterns.unwrap_or_default();
        v.push(input.into());
        self.exclude_attachment_file_patterns = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of regular expression patterns applied to exclude certain knowledge article attachments. Attachments that match the patterns are excluded from the index. Items that don't match the patterns are included in the index. If an item matches both an inclusion and exclusion pattern, the exclusion pattern takes precedence and the item isn't included in the index.</p>
    pub fn set_exclude_attachment_file_patterns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.exclude_attachment_file_patterns = input;
        self
    }
    /// <p>A list of regular expression patterns applied to exclude certain knowledge article attachments. Attachments that match the patterns are excluded from the index. Items that don't match the patterns are included in the index. If an item matches both an inclusion and exclusion pattern, the exclusion pattern takes precedence and the item isn't included in the index.</p>
    pub fn get_exclude_attachment_file_patterns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.exclude_attachment_file_patterns
    }
    /// <p>The name of the ServiceNow field that is mapped to the index document contents field in the Amazon Kendra index.</p>
    /// This field is required.
    pub fn document_data_field_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.document_data_field_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the ServiceNow field that is mapped to the index document contents field in the Amazon Kendra index.</p>
    pub fn set_document_data_field_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.document_data_field_name = input;
        self
    }
    /// <p>The name of the ServiceNow field that is mapped to the index document contents field in the Amazon Kendra index.</p>
    pub fn get_document_data_field_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.document_data_field_name
    }
    /// <p>The name of the ServiceNow field that is mapped to the index document title field.</p>
    pub fn document_title_field_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.document_title_field_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the ServiceNow field that is mapped to the index document title field.</p>
    pub fn set_document_title_field_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.document_title_field_name = input;
        self
    }
    /// <p>The name of the ServiceNow field that is mapped to the index document title field.</p>
    pub fn get_document_title_field_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.document_title_field_name
    }
    /// Appends an item to `field_mappings`.
    ///
    /// To override the contents of this collection use [`set_field_mappings`](Self::set_field_mappings).
    ///
    /// <p>Maps attributes or field names of knoweldge articles to Amazon Kendra index field names. To create custom fields, use the <code>UpdateIndex</code> API before you map to ServiceNow fields. For more information, see <a href="https://docs.aws.amazon.com/kendra/latest/dg/field-mapping.html">Mapping data source fields</a>. The ServiceNow data source field names must exist in your ServiceNow custom metadata.</p>
    pub fn field_mappings(mut self, input: crate::types::DataSourceToIndexFieldMapping) -> Self {
        let mut v = self.field_mappings.unwrap_or_default();
        v.push(input);
        self.field_mappings = ::std::option::Option::Some(v);
        self
    }
    /// <p>Maps attributes or field names of knoweldge articles to Amazon Kendra index field names. To create custom fields, use the <code>UpdateIndex</code> API before you map to ServiceNow fields. For more information, see <a href="https://docs.aws.amazon.com/kendra/latest/dg/field-mapping.html">Mapping data source fields</a>. The ServiceNow data source field names must exist in your ServiceNow custom metadata.</p>
    pub fn set_field_mappings(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DataSourceToIndexFieldMapping>>) -> Self {
        self.field_mappings = input;
        self
    }
    /// <p>Maps attributes or field names of knoweldge articles to Amazon Kendra index field names. To create custom fields, use the <code>UpdateIndex</code> API before you map to ServiceNow fields. For more information, see <a href="https://docs.aws.amazon.com/kendra/latest/dg/field-mapping.html">Mapping data source fields</a>. The ServiceNow data source field names must exist in your ServiceNow custom metadata.</p>
    pub fn get_field_mappings(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DataSourceToIndexFieldMapping>> {
        &self.field_mappings
    }
    /// <p>A query that selects the knowledge articles to index. The query can return articles from multiple knowledge bases, and the knowledge bases can be public or private.</p>
    /// <p>The query string must be one generated by the ServiceNow console. For more information, see <a href="https://docs.aws.amazon.com/kendra/latest/dg/servicenow-query.html">Specifying documents to index with a query</a>.</p>
    pub fn filter_query(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.filter_query = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A query that selects the knowledge articles to index. The query can return articles from multiple knowledge bases, and the knowledge bases can be public or private.</p>
    /// <p>The query string must be one generated by the ServiceNow console. For more information, see <a href="https://docs.aws.amazon.com/kendra/latest/dg/servicenow-query.html">Specifying documents to index with a query</a>.</p>
    pub fn set_filter_query(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.filter_query = input;
        self
    }
    /// <p>A query that selects the knowledge articles to index. The query can return articles from multiple knowledge bases, and the knowledge bases can be public or private.</p>
    /// <p>The query string must be one generated by the ServiceNow console. For more information, see <a href="https://docs.aws.amazon.com/kendra/latest/dg/servicenow-query.html">Specifying documents to index with a query</a>.</p>
    pub fn get_filter_query(&self) -> &::std::option::Option<::std::string::String> {
        &self.filter_query
    }
    /// Consumes the builder and constructs a [`ServiceNowKnowledgeArticleConfiguration`](crate::types::ServiceNowKnowledgeArticleConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`document_data_field_name`](crate::types::builders::ServiceNowKnowledgeArticleConfigurationBuilder::document_data_field_name)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::ServiceNowKnowledgeArticleConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ServiceNowKnowledgeArticleConfiguration {
            crawl_attachments: self.crawl_attachments.unwrap_or_default(),
            include_attachment_file_patterns: self.include_attachment_file_patterns,
            exclude_attachment_file_patterns: self.exclude_attachment_file_patterns,
            document_data_field_name: self.document_data_field_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "document_data_field_name",
                    "document_data_field_name was not specified but it is required when building ServiceNowKnowledgeArticleConfiguration",
                )
            })?,
            document_title_field_name: self.document_title_field_name,
            field_mappings: self.field_mappings,
            filter_query: self.filter_query,
        })
    }
}
