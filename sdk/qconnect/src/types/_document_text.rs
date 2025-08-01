// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The text of the document.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct DocumentText {
    /// <p>Text in the document.</p>
    pub text: ::std::option::Option<::std::string::String>,
    /// <p>Highlights in the document text.</p>
    pub highlights: ::std::option::Option<::std::vec::Vec<crate::types::Highlight>>,
}
impl DocumentText {
    /// <p>Text in the document.</p>
    pub fn text(&self) -> ::std::option::Option<&str> {
        self.text.as_deref()
    }
    /// <p>Highlights in the document text.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.highlights.is_none()`.
    pub fn highlights(&self) -> &[crate::types::Highlight] {
        self.highlights.as_deref().unwrap_or_default()
    }
}
impl ::std::fmt::Debug for DocumentText {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("DocumentText");
        formatter.field("text", &"*** Sensitive Data Redacted ***");
        formatter.field("highlights", &self.highlights);
        formatter.finish()
    }
}
impl DocumentText {
    /// Creates a new builder-style object to manufacture [`DocumentText`](crate::types::DocumentText).
    pub fn builder() -> crate::types::builders::DocumentTextBuilder {
        crate::types::builders::DocumentTextBuilder::default()
    }
}

/// A builder for [`DocumentText`](crate::types::DocumentText).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct DocumentTextBuilder {
    pub(crate) text: ::std::option::Option<::std::string::String>,
    pub(crate) highlights: ::std::option::Option<::std::vec::Vec<crate::types::Highlight>>,
}
impl DocumentTextBuilder {
    /// <p>Text in the document.</p>
    pub fn text(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.text = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Text in the document.</p>
    pub fn set_text(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.text = input;
        self
    }
    /// <p>Text in the document.</p>
    pub fn get_text(&self) -> &::std::option::Option<::std::string::String> {
        &self.text
    }
    /// Appends an item to `highlights`.
    ///
    /// To override the contents of this collection use [`set_highlights`](Self::set_highlights).
    ///
    /// <p>Highlights in the document text.</p>
    pub fn highlights(mut self, input: crate::types::Highlight) -> Self {
        let mut v = self.highlights.unwrap_or_default();
        v.push(input);
        self.highlights = ::std::option::Option::Some(v);
        self
    }
    /// <p>Highlights in the document text.</p>
    pub fn set_highlights(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Highlight>>) -> Self {
        self.highlights = input;
        self
    }
    /// <p>Highlights in the document text.</p>
    pub fn get_highlights(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Highlight>> {
        &self.highlights
    }
    /// Consumes the builder and constructs a [`DocumentText`](crate::types::DocumentText).
    pub fn build(self) -> crate::types::DocumentText {
        crate::types::DocumentText {
            text: self.text,
            highlights: self.highlights,
        }
    }
}
impl ::std::fmt::Debug for DocumentTextBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("DocumentTextBuilder");
        formatter.field("text", &"*** Sensitive Data Redacted ***");
        formatter.field("highlights", &self.highlights);
        formatter.finish()
    }
}
