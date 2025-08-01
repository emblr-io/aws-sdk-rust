// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The documents used to generate an Amazon Q Business web experience response.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SourceAttribution {
    /// <p>The title of the document which is the source for the Amazon Q Business generated response.</p>
    pub title: ::std::option::Option<::std::string::String>,
    /// <p>The content extract from the document on which the generated response is based.</p>
    pub snippet: ::std::option::Option<::std::string::String>,
    /// <p>The URL of the document which is the source for the Amazon Q Business generated response.</p>
    pub url: ::std::option::Option<::std::string::String>,
    /// <p>The number attached to a citation in an Amazon Q Business generated response.</p>
    pub citation_number: ::std::option::Option<i32>,
    /// <p>The Unix timestamp when the Amazon Q Business application was last updated.</p>
    pub updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>A text extract from a source document that is used for source attribution.</p>
    pub text_message_segments: ::std::option::Option<::std::vec::Vec<crate::types::TextSegment>>,
}
impl SourceAttribution {
    /// <p>The title of the document which is the source for the Amazon Q Business generated response.</p>
    pub fn title(&self) -> ::std::option::Option<&str> {
        self.title.as_deref()
    }
    /// <p>The content extract from the document on which the generated response is based.</p>
    pub fn snippet(&self) -> ::std::option::Option<&str> {
        self.snippet.as_deref()
    }
    /// <p>The URL of the document which is the source for the Amazon Q Business generated response.</p>
    pub fn url(&self) -> ::std::option::Option<&str> {
        self.url.as_deref()
    }
    /// <p>The number attached to a citation in an Amazon Q Business generated response.</p>
    pub fn citation_number(&self) -> ::std::option::Option<i32> {
        self.citation_number
    }
    /// <p>The Unix timestamp when the Amazon Q Business application was last updated.</p>
    pub fn updated_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.updated_at.as_ref()
    }
    /// <p>A text extract from a source document that is used for source attribution.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.text_message_segments.is_none()`.
    pub fn text_message_segments(&self) -> &[crate::types::TextSegment] {
        self.text_message_segments.as_deref().unwrap_or_default()
    }
}
impl SourceAttribution {
    /// Creates a new builder-style object to manufacture [`SourceAttribution`](crate::types::SourceAttribution).
    pub fn builder() -> crate::types::builders::SourceAttributionBuilder {
        crate::types::builders::SourceAttributionBuilder::default()
    }
}

/// A builder for [`SourceAttribution`](crate::types::SourceAttribution).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SourceAttributionBuilder {
    pub(crate) title: ::std::option::Option<::std::string::String>,
    pub(crate) snippet: ::std::option::Option<::std::string::String>,
    pub(crate) url: ::std::option::Option<::std::string::String>,
    pub(crate) citation_number: ::std::option::Option<i32>,
    pub(crate) updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) text_message_segments: ::std::option::Option<::std::vec::Vec<crate::types::TextSegment>>,
}
impl SourceAttributionBuilder {
    /// <p>The title of the document which is the source for the Amazon Q Business generated response.</p>
    pub fn title(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.title = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The title of the document which is the source for the Amazon Q Business generated response.</p>
    pub fn set_title(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.title = input;
        self
    }
    /// <p>The title of the document which is the source for the Amazon Q Business generated response.</p>
    pub fn get_title(&self) -> &::std::option::Option<::std::string::String> {
        &self.title
    }
    /// <p>The content extract from the document on which the generated response is based.</p>
    pub fn snippet(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.snippet = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The content extract from the document on which the generated response is based.</p>
    pub fn set_snippet(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.snippet = input;
        self
    }
    /// <p>The content extract from the document on which the generated response is based.</p>
    pub fn get_snippet(&self) -> &::std::option::Option<::std::string::String> {
        &self.snippet
    }
    /// <p>The URL of the document which is the source for the Amazon Q Business generated response.</p>
    pub fn url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The URL of the document which is the source for the Amazon Q Business generated response.</p>
    pub fn set_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.url = input;
        self
    }
    /// <p>The URL of the document which is the source for the Amazon Q Business generated response.</p>
    pub fn get_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.url
    }
    /// <p>The number attached to a citation in an Amazon Q Business generated response.</p>
    pub fn citation_number(mut self, input: i32) -> Self {
        self.citation_number = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number attached to a citation in an Amazon Q Business generated response.</p>
    pub fn set_citation_number(mut self, input: ::std::option::Option<i32>) -> Self {
        self.citation_number = input;
        self
    }
    /// <p>The number attached to a citation in an Amazon Q Business generated response.</p>
    pub fn get_citation_number(&self) -> &::std::option::Option<i32> {
        &self.citation_number
    }
    /// <p>The Unix timestamp when the Amazon Q Business application was last updated.</p>
    pub fn updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Unix timestamp when the Amazon Q Business application was last updated.</p>
    pub fn set_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.updated_at = input;
        self
    }
    /// <p>The Unix timestamp when the Amazon Q Business application was last updated.</p>
    pub fn get_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.updated_at
    }
    /// Appends an item to `text_message_segments`.
    ///
    /// To override the contents of this collection use [`set_text_message_segments`](Self::set_text_message_segments).
    ///
    /// <p>A text extract from a source document that is used for source attribution.</p>
    pub fn text_message_segments(mut self, input: crate::types::TextSegment) -> Self {
        let mut v = self.text_message_segments.unwrap_or_default();
        v.push(input);
        self.text_message_segments = ::std::option::Option::Some(v);
        self
    }
    /// <p>A text extract from a source document that is used for source attribution.</p>
    pub fn set_text_message_segments(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::TextSegment>>) -> Self {
        self.text_message_segments = input;
        self
    }
    /// <p>A text extract from a source document that is used for source attribution.</p>
    pub fn get_text_message_segments(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::TextSegment>> {
        &self.text_message_segments
    }
    /// Consumes the builder and constructs a [`SourceAttribution`](crate::types::SourceAttribution).
    pub fn build(self) -> crate::types::SourceAttribution {
        crate::types::SourceAttribution {
            title: self.title,
            snippet: self.snippet,
            url: self.url,
            citation_number: self.citation_number,
            updated_at: self.updated_at,
            text_message_segments: self.text_message_segments,
        }
    }
}
