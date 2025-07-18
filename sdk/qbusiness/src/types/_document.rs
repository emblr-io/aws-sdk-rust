// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A document in an Amazon Q Business application.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Document {
    /// <p>The identifier of the document.</p>
    pub id: ::std::string::String,
    /// <p>Custom attributes to apply to the document for refining Amazon Q Business web experience responses.</p>
    pub attributes: ::std::option::Option<::std::vec::Vec<crate::types::DocumentAttribute>>,
    /// <p>The contents of the document.</p>
    pub content: ::std::option::Option<crate::types::DocumentContent>,
    /// <p>The file type of the document in the Blob field.</p>
    /// <p>If you want to index snippets or subsets of HTML documents instead of the entirety of the HTML documents, you add the <code>HTML</code> start and closing tags (<code>&lt;HTML&gt;content&lt;/HTML&gt;</code>) around the content.</p>
    pub content_type: ::std::option::Option<crate::types::ContentType>,
    /// <p>The title of the document.</p>
    pub title: ::std::option::Option<::std::string::String>,
    /// <p>Configuration information for access permission to a document.</p>
    pub access_configuration: ::std::option::Option<crate::types::AccessConfiguration>,
    /// <p>The configuration information for altering document metadata and content during the document ingestion process.</p>
    pub document_enrichment_configuration: ::std::option::Option<crate::types::DocumentEnrichmentConfiguration>,
    /// <p>The configuration for extracting information from media in the document.</p>
    pub media_extraction_configuration: ::std::option::Option<crate::types::MediaExtractionConfiguration>,
}
impl Document {
    /// <p>The identifier of the document.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>Custom attributes to apply to the document for refining Amazon Q Business web experience responses.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.attributes.is_none()`.
    pub fn attributes(&self) -> &[crate::types::DocumentAttribute] {
        self.attributes.as_deref().unwrap_or_default()
    }
    /// <p>The contents of the document.</p>
    pub fn content(&self) -> ::std::option::Option<&crate::types::DocumentContent> {
        self.content.as_ref()
    }
    /// <p>The file type of the document in the Blob field.</p>
    /// <p>If you want to index snippets or subsets of HTML documents instead of the entirety of the HTML documents, you add the <code>HTML</code> start and closing tags (<code>&lt;HTML&gt;content&lt;/HTML&gt;</code>) around the content.</p>
    pub fn content_type(&self) -> ::std::option::Option<&crate::types::ContentType> {
        self.content_type.as_ref()
    }
    /// <p>The title of the document.</p>
    pub fn title(&self) -> ::std::option::Option<&str> {
        self.title.as_deref()
    }
    /// <p>Configuration information for access permission to a document.</p>
    pub fn access_configuration(&self) -> ::std::option::Option<&crate::types::AccessConfiguration> {
        self.access_configuration.as_ref()
    }
    /// <p>The configuration information for altering document metadata and content during the document ingestion process.</p>
    pub fn document_enrichment_configuration(&self) -> ::std::option::Option<&crate::types::DocumentEnrichmentConfiguration> {
        self.document_enrichment_configuration.as_ref()
    }
    /// <p>The configuration for extracting information from media in the document.</p>
    pub fn media_extraction_configuration(&self) -> ::std::option::Option<&crate::types::MediaExtractionConfiguration> {
        self.media_extraction_configuration.as_ref()
    }
}
impl Document {
    /// Creates a new builder-style object to manufacture [`Document`](crate::types::Document).
    pub fn builder() -> crate::types::builders::DocumentBuilder {
        crate::types::builders::DocumentBuilder::default()
    }
}

/// A builder for [`Document`](crate::types::Document).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DocumentBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) attributes: ::std::option::Option<::std::vec::Vec<crate::types::DocumentAttribute>>,
    pub(crate) content: ::std::option::Option<crate::types::DocumentContent>,
    pub(crate) content_type: ::std::option::Option<crate::types::ContentType>,
    pub(crate) title: ::std::option::Option<::std::string::String>,
    pub(crate) access_configuration: ::std::option::Option<crate::types::AccessConfiguration>,
    pub(crate) document_enrichment_configuration: ::std::option::Option<crate::types::DocumentEnrichmentConfiguration>,
    pub(crate) media_extraction_configuration: ::std::option::Option<crate::types::MediaExtractionConfiguration>,
}
impl DocumentBuilder {
    /// <p>The identifier of the document.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the document.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The identifier of the document.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// Appends an item to `attributes`.
    ///
    /// To override the contents of this collection use [`set_attributes`](Self::set_attributes).
    ///
    /// <p>Custom attributes to apply to the document for refining Amazon Q Business web experience responses.</p>
    pub fn attributes(mut self, input: crate::types::DocumentAttribute) -> Self {
        let mut v = self.attributes.unwrap_or_default();
        v.push(input);
        self.attributes = ::std::option::Option::Some(v);
        self
    }
    /// <p>Custom attributes to apply to the document for refining Amazon Q Business web experience responses.</p>
    pub fn set_attributes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DocumentAttribute>>) -> Self {
        self.attributes = input;
        self
    }
    /// <p>Custom attributes to apply to the document for refining Amazon Q Business web experience responses.</p>
    pub fn get_attributes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DocumentAttribute>> {
        &self.attributes
    }
    /// <p>The contents of the document.</p>
    pub fn content(mut self, input: crate::types::DocumentContent) -> Self {
        self.content = ::std::option::Option::Some(input);
        self
    }
    /// <p>The contents of the document.</p>
    pub fn set_content(mut self, input: ::std::option::Option<crate::types::DocumentContent>) -> Self {
        self.content = input;
        self
    }
    /// <p>The contents of the document.</p>
    pub fn get_content(&self) -> &::std::option::Option<crate::types::DocumentContent> {
        &self.content
    }
    /// <p>The file type of the document in the Blob field.</p>
    /// <p>If you want to index snippets or subsets of HTML documents instead of the entirety of the HTML documents, you add the <code>HTML</code> start and closing tags (<code>&lt;HTML&gt;content&lt;/HTML&gt;</code>) around the content.</p>
    pub fn content_type(mut self, input: crate::types::ContentType) -> Self {
        self.content_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The file type of the document in the Blob field.</p>
    /// <p>If you want to index snippets or subsets of HTML documents instead of the entirety of the HTML documents, you add the <code>HTML</code> start and closing tags (<code>&lt;HTML&gt;content&lt;/HTML&gt;</code>) around the content.</p>
    pub fn set_content_type(mut self, input: ::std::option::Option<crate::types::ContentType>) -> Self {
        self.content_type = input;
        self
    }
    /// <p>The file type of the document in the Blob field.</p>
    /// <p>If you want to index snippets or subsets of HTML documents instead of the entirety of the HTML documents, you add the <code>HTML</code> start and closing tags (<code>&lt;HTML&gt;content&lt;/HTML&gt;</code>) around the content.</p>
    pub fn get_content_type(&self) -> &::std::option::Option<crate::types::ContentType> {
        &self.content_type
    }
    /// <p>The title of the document.</p>
    pub fn title(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.title = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The title of the document.</p>
    pub fn set_title(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.title = input;
        self
    }
    /// <p>The title of the document.</p>
    pub fn get_title(&self) -> &::std::option::Option<::std::string::String> {
        &self.title
    }
    /// <p>Configuration information for access permission to a document.</p>
    pub fn access_configuration(mut self, input: crate::types::AccessConfiguration) -> Self {
        self.access_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Configuration information for access permission to a document.</p>
    pub fn set_access_configuration(mut self, input: ::std::option::Option<crate::types::AccessConfiguration>) -> Self {
        self.access_configuration = input;
        self
    }
    /// <p>Configuration information for access permission to a document.</p>
    pub fn get_access_configuration(&self) -> &::std::option::Option<crate::types::AccessConfiguration> {
        &self.access_configuration
    }
    /// <p>The configuration information for altering document metadata and content during the document ingestion process.</p>
    pub fn document_enrichment_configuration(mut self, input: crate::types::DocumentEnrichmentConfiguration) -> Self {
        self.document_enrichment_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration information for altering document metadata and content during the document ingestion process.</p>
    pub fn set_document_enrichment_configuration(mut self, input: ::std::option::Option<crate::types::DocumentEnrichmentConfiguration>) -> Self {
        self.document_enrichment_configuration = input;
        self
    }
    /// <p>The configuration information for altering document metadata and content during the document ingestion process.</p>
    pub fn get_document_enrichment_configuration(&self) -> &::std::option::Option<crate::types::DocumentEnrichmentConfiguration> {
        &self.document_enrichment_configuration
    }
    /// <p>The configuration for extracting information from media in the document.</p>
    pub fn media_extraction_configuration(mut self, input: crate::types::MediaExtractionConfiguration) -> Self {
        self.media_extraction_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration for extracting information from media in the document.</p>
    pub fn set_media_extraction_configuration(mut self, input: ::std::option::Option<crate::types::MediaExtractionConfiguration>) -> Self {
        self.media_extraction_configuration = input;
        self
    }
    /// <p>The configuration for extracting information from media in the document.</p>
    pub fn get_media_extraction_configuration(&self) -> &::std::option::Option<crate::types::MediaExtractionConfiguration> {
        &self.media_extraction_configuration
    }
    /// Consumes the builder and constructs a [`Document`](crate::types::Document).
    /// This method will fail if any of the following fields are not set:
    /// - [`id`](crate::types::builders::DocumentBuilder::id)
    pub fn build(self) -> ::std::result::Result<crate::types::Document, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Document {
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building Document",
                )
            })?,
            attributes: self.attributes,
            content: self.content,
            content_type: self.content_type,
            title: self.title,
            access_configuration: self.access_configuration,
            document_enrichment_configuration: self.document_enrichment_configuration,
            media_extraction_configuration: self.media_extraction_configuration,
        })
    }
}
