// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details about the source content text data.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TextData {
    /// <p>The text of the document.</p>
    pub title: ::std::option::Option<crate::types::DocumentText>,
    /// <p>The text of the document.</p>
    pub excerpt: ::std::option::Option<crate::types::DocumentText>,
}
impl TextData {
    /// <p>The text of the document.</p>
    pub fn title(&self) -> ::std::option::Option<&crate::types::DocumentText> {
        self.title.as_ref()
    }
    /// <p>The text of the document.</p>
    pub fn excerpt(&self) -> ::std::option::Option<&crate::types::DocumentText> {
        self.excerpt.as_ref()
    }
}
impl TextData {
    /// Creates a new builder-style object to manufacture [`TextData`](crate::types::TextData).
    pub fn builder() -> crate::types::builders::TextDataBuilder {
        crate::types::builders::TextDataBuilder::default()
    }
}

/// A builder for [`TextData`](crate::types::TextData).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TextDataBuilder {
    pub(crate) title: ::std::option::Option<crate::types::DocumentText>,
    pub(crate) excerpt: ::std::option::Option<crate::types::DocumentText>,
}
impl TextDataBuilder {
    /// <p>The text of the document.</p>
    pub fn title(mut self, input: crate::types::DocumentText) -> Self {
        self.title = ::std::option::Option::Some(input);
        self
    }
    /// <p>The text of the document.</p>
    pub fn set_title(mut self, input: ::std::option::Option<crate::types::DocumentText>) -> Self {
        self.title = input;
        self
    }
    /// <p>The text of the document.</p>
    pub fn get_title(&self) -> &::std::option::Option<crate::types::DocumentText> {
        &self.title
    }
    /// <p>The text of the document.</p>
    pub fn excerpt(mut self, input: crate::types::DocumentText) -> Self {
        self.excerpt = ::std::option::Option::Some(input);
        self
    }
    /// <p>The text of the document.</p>
    pub fn set_excerpt(mut self, input: ::std::option::Option<crate::types::DocumentText>) -> Self {
        self.excerpt = input;
        self
    }
    /// <p>The text of the document.</p>
    pub fn get_excerpt(&self) -> &::std::option::Option<crate::types::DocumentText> {
        &self.excerpt
    }
    /// Consumes the builder and constructs a [`TextData`](crate::types::TextData).
    pub fn build(self) -> crate::types::TextData {
        crate::types::TextData {
            title: self.title,
            excerpt: self.excerpt,
        }
    }
}
