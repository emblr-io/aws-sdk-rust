// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the relevant text excerpt from a source that was used to generate a citation text segment in an Amazon Q Business chat response.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SnippetExcerpt {
    /// <p>The relevant text excerpt from a source that was used to generate a citation text segment in an Amazon Q chat response.</p>
    pub text: ::std::option::Option<::std::string::String>,
}
impl SnippetExcerpt {
    /// <p>The relevant text excerpt from a source that was used to generate a citation text segment in an Amazon Q chat response.</p>
    pub fn text(&self) -> ::std::option::Option<&str> {
        self.text.as_deref()
    }
}
impl SnippetExcerpt {
    /// Creates a new builder-style object to manufacture [`SnippetExcerpt`](crate::types::SnippetExcerpt).
    pub fn builder() -> crate::types::builders::SnippetExcerptBuilder {
        crate::types::builders::SnippetExcerptBuilder::default()
    }
}

/// A builder for [`SnippetExcerpt`](crate::types::SnippetExcerpt).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SnippetExcerptBuilder {
    pub(crate) text: ::std::option::Option<::std::string::String>,
}
impl SnippetExcerptBuilder {
    /// <p>The relevant text excerpt from a source that was used to generate a citation text segment in an Amazon Q chat response.</p>
    pub fn text(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.text = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The relevant text excerpt from a source that was used to generate a citation text segment in an Amazon Q chat response.</p>
    pub fn set_text(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.text = input;
        self
    }
    /// <p>The relevant text excerpt from a source that was used to generate a citation text segment in an Amazon Q chat response.</p>
    pub fn get_text(&self) -> &::std::option::Option<::std::string::String> {
        &self.text
    }
    /// Consumes the builder and constructs a [`SnippetExcerpt`](crate::types::SnippetExcerpt).
    pub fn build(self) -> crate::types::SnippetExcerpt {
        crate::types::SnippetExcerpt { text: self.text }
    }
}
