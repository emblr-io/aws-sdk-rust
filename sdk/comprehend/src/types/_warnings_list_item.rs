// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The system identified one of the following warnings while processing the input document:</p>
/// <ul>
/// <li>
/// <p>The document to classify is plain text, but the classifier is a native document model.</p></li>
/// <li>
/// <p>The document to classify is semi-structured, but the classifier is a plain-text model.</p></li>
/// </ul>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct WarningsListItem {
    /// <p>Page number in the input document.</p>
    pub page: ::std::option::Option<i32>,
    /// <p>The type of warning.</p>
    pub warn_code: ::std::option::Option<crate::types::PageBasedWarningCode>,
    /// <p>Text message associated with the warning.</p>
    pub warn_message: ::std::option::Option<::std::string::String>,
}
impl WarningsListItem {
    /// <p>Page number in the input document.</p>
    pub fn page(&self) -> ::std::option::Option<i32> {
        self.page
    }
    /// <p>The type of warning.</p>
    pub fn warn_code(&self) -> ::std::option::Option<&crate::types::PageBasedWarningCode> {
        self.warn_code.as_ref()
    }
    /// <p>Text message associated with the warning.</p>
    pub fn warn_message(&self) -> ::std::option::Option<&str> {
        self.warn_message.as_deref()
    }
}
impl WarningsListItem {
    /// Creates a new builder-style object to manufacture [`WarningsListItem`](crate::types::WarningsListItem).
    pub fn builder() -> crate::types::builders::WarningsListItemBuilder {
        crate::types::builders::WarningsListItemBuilder::default()
    }
}

/// A builder for [`WarningsListItem`](crate::types::WarningsListItem).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct WarningsListItemBuilder {
    pub(crate) page: ::std::option::Option<i32>,
    pub(crate) warn_code: ::std::option::Option<crate::types::PageBasedWarningCode>,
    pub(crate) warn_message: ::std::option::Option<::std::string::String>,
}
impl WarningsListItemBuilder {
    /// <p>Page number in the input document.</p>
    pub fn page(mut self, input: i32) -> Self {
        self.page = ::std::option::Option::Some(input);
        self
    }
    /// <p>Page number in the input document.</p>
    pub fn set_page(mut self, input: ::std::option::Option<i32>) -> Self {
        self.page = input;
        self
    }
    /// <p>Page number in the input document.</p>
    pub fn get_page(&self) -> &::std::option::Option<i32> {
        &self.page
    }
    /// <p>The type of warning.</p>
    pub fn warn_code(mut self, input: crate::types::PageBasedWarningCode) -> Self {
        self.warn_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of warning.</p>
    pub fn set_warn_code(mut self, input: ::std::option::Option<crate::types::PageBasedWarningCode>) -> Self {
        self.warn_code = input;
        self
    }
    /// <p>The type of warning.</p>
    pub fn get_warn_code(&self) -> &::std::option::Option<crate::types::PageBasedWarningCode> {
        &self.warn_code
    }
    /// <p>Text message associated with the warning.</p>
    pub fn warn_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.warn_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Text message associated with the warning.</p>
    pub fn set_warn_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.warn_message = input;
        self
    }
    /// <p>Text message associated with the warning.</p>
    pub fn get_warn_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.warn_message
    }
    /// Consumes the builder and constructs a [`WarningsListItem`](crate::types::WarningsListItem).
    pub fn build(self) -> crate::types::WarningsListItem {
        crate::types::WarningsListItem {
            page: self.page,
            warn_code: self.warn_code,
            warn_message: self.warn_message,
        }
    }
}
