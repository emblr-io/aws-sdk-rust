// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the components of a notification message.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MessageComponents {
    /// <p>A sentence long summary. For example, titles or an email subject line.</p>
    pub headline: ::std::option::Option<::std::string::String>,
    /// <p>A paragraph long or multiple sentence summary. For example, Chatbot notifications.</p>
    pub paragraph_summary: ::std::option::Option<::std::string::String>,
    /// <p>A complete summary with all possible relevant information.</p>
    pub complete_description: ::std::option::Option<::std::string::String>,
    /// <p>A list of properties in key-value pairs. Pairs are shown in order of importance from most important to least important. Channels may limit the number of dimensions shown to the notification viewer.</p><note>
    /// <p>Included dimensions, keys, and values are subject to change.</p>
    /// </note>
    pub dimensions: ::std::option::Option<::std::vec::Vec<crate::types::Dimension>>,
}
impl MessageComponents {
    /// <p>A sentence long summary. For example, titles or an email subject line.</p>
    pub fn headline(&self) -> ::std::option::Option<&str> {
        self.headline.as_deref()
    }
    /// <p>A paragraph long or multiple sentence summary. For example, Chatbot notifications.</p>
    pub fn paragraph_summary(&self) -> ::std::option::Option<&str> {
        self.paragraph_summary.as_deref()
    }
    /// <p>A complete summary with all possible relevant information.</p>
    pub fn complete_description(&self) -> ::std::option::Option<&str> {
        self.complete_description.as_deref()
    }
    /// <p>A list of properties in key-value pairs. Pairs are shown in order of importance from most important to least important. Channels may limit the number of dimensions shown to the notification viewer.</p><note>
    /// <p>Included dimensions, keys, and values are subject to change.</p>
    /// </note>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.dimensions.is_none()`.
    pub fn dimensions(&self) -> &[crate::types::Dimension] {
        self.dimensions.as_deref().unwrap_or_default()
    }
}
impl MessageComponents {
    /// Creates a new builder-style object to manufacture [`MessageComponents`](crate::types::MessageComponents).
    pub fn builder() -> crate::types::builders::MessageComponentsBuilder {
        crate::types::builders::MessageComponentsBuilder::default()
    }
}

/// A builder for [`MessageComponents`](crate::types::MessageComponents).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MessageComponentsBuilder {
    pub(crate) headline: ::std::option::Option<::std::string::String>,
    pub(crate) paragraph_summary: ::std::option::Option<::std::string::String>,
    pub(crate) complete_description: ::std::option::Option<::std::string::String>,
    pub(crate) dimensions: ::std::option::Option<::std::vec::Vec<crate::types::Dimension>>,
}
impl MessageComponentsBuilder {
    /// <p>A sentence long summary. For example, titles or an email subject line.</p>
    pub fn headline(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.headline = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A sentence long summary. For example, titles or an email subject line.</p>
    pub fn set_headline(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.headline = input;
        self
    }
    /// <p>A sentence long summary. For example, titles or an email subject line.</p>
    pub fn get_headline(&self) -> &::std::option::Option<::std::string::String> {
        &self.headline
    }
    /// <p>A paragraph long or multiple sentence summary. For example, Chatbot notifications.</p>
    pub fn paragraph_summary(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.paragraph_summary = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A paragraph long or multiple sentence summary. For example, Chatbot notifications.</p>
    pub fn set_paragraph_summary(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.paragraph_summary = input;
        self
    }
    /// <p>A paragraph long or multiple sentence summary. For example, Chatbot notifications.</p>
    pub fn get_paragraph_summary(&self) -> &::std::option::Option<::std::string::String> {
        &self.paragraph_summary
    }
    /// <p>A complete summary with all possible relevant information.</p>
    pub fn complete_description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.complete_description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A complete summary with all possible relevant information.</p>
    pub fn set_complete_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.complete_description = input;
        self
    }
    /// <p>A complete summary with all possible relevant information.</p>
    pub fn get_complete_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.complete_description
    }
    /// Appends an item to `dimensions`.
    ///
    /// To override the contents of this collection use [`set_dimensions`](Self::set_dimensions).
    ///
    /// <p>A list of properties in key-value pairs. Pairs are shown in order of importance from most important to least important. Channels may limit the number of dimensions shown to the notification viewer.</p><note>
    /// <p>Included dimensions, keys, and values are subject to change.</p>
    /// </note>
    pub fn dimensions(mut self, input: crate::types::Dimension) -> Self {
        let mut v = self.dimensions.unwrap_or_default();
        v.push(input);
        self.dimensions = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of properties in key-value pairs. Pairs are shown in order of importance from most important to least important. Channels may limit the number of dimensions shown to the notification viewer.</p><note>
    /// <p>Included dimensions, keys, and values are subject to change.</p>
    /// </note>
    pub fn set_dimensions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Dimension>>) -> Self {
        self.dimensions = input;
        self
    }
    /// <p>A list of properties in key-value pairs. Pairs are shown in order of importance from most important to least important. Channels may limit the number of dimensions shown to the notification viewer.</p><note>
    /// <p>Included dimensions, keys, and values are subject to change.</p>
    /// </note>
    pub fn get_dimensions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Dimension>> {
        &self.dimensions
    }
    /// Consumes the builder and constructs a [`MessageComponents`](crate::types::MessageComponents).
    pub fn build(self) -> crate::types::MessageComponents {
        crate::types::MessageComponents {
            headline: self.headline,
            paragraph_summary: self.paragraph_summary,
            complete_description: self.complete_description,
            dimensions: self.dimensions,
        }
    }
}
