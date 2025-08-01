// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The translated content.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct TranslatedDocument {
    /// <p>The document containing the translated content.</p>
    pub content: ::aws_smithy_types::Blob,
}
impl TranslatedDocument {
    /// <p>The document containing the translated content.</p>
    pub fn content(&self) -> &::aws_smithy_types::Blob {
        &self.content
    }
}
impl ::std::fmt::Debug for TranslatedDocument {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("TranslatedDocument");
        formatter.field("content", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl TranslatedDocument {
    /// Creates a new builder-style object to manufacture [`TranslatedDocument`](crate::types::TranslatedDocument).
    pub fn builder() -> crate::types::builders::TranslatedDocumentBuilder {
        crate::types::builders::TranslatedDocumentBuilder::default()
    }
}

/// A builder for [`TranslatedDocument`](crate::types::TranslatedDocument).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct TranslatedDocumentBuilder {
    pub(crate) content: ::std::option::Option<::aws_smithy_types::Blob>,
}
impl TranslatedDocumentBuilder {
    /// <p>The document containing the translated content.</p>
    /// This field is required.
    pub fn content(mut self, input: ::aws_smithy_types::Blob) -> Self {
        self.content = ::std::option::Option::Some(input);
        self
    }
    /// <p>The document containing the translated content.</p>
    pub fn set_content(mut self, input: ::std::option::Option<::aws_smithy_types::Blob>) -> Self {
        self.content = input;
        self
    }
    /// <p>The document containing the translated content.</p>
    pub fn get_content(&self) -> &::std::option::Option<::aws_smithy_types::Blob> {
        &self.content
    }
    /// Consumes the builder and constructs a [`TranslatedDocument`](crate::types::TranslatedDocument).
    /// This method will fail if any of the following fields are not set:
    /// - [`content`](crate::types::builders::TranslatedDocumentBuilder::content)
    pub fn build(self) -> ::std::result::Result<crate::types::TranslatedDocument, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::TranslatedDocument {
            content: self.content.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "content",
                    "content was not specified but it is required when building TranslatedDocument",
                )
            })?,
        })
    }
}
impl ::std::fmt::Debug for TranslatedDocumentBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("TranslatedDocumentBuilder");
        formatter.field("content", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
