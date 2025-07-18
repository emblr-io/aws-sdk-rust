// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateDocumentMetadataInput {
    /// <p>The name of the change template for which a version's metadata is to be updated.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The version of a change template in which to update approval metadata.</p>
    pub document_version: ::std::option::Option<::std::string::String>,
    /// <p>The change template review details to update.</p>
    pub document_reviews: ::std::option::Option<crate::types::DocumentReviews>,
}
impl UpdateDocumentMetadataInput {
    /// <p>The name of the change template for which a version's metadata is to be updated.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The version of a change template in which to update approval metadata.</p>
    pub fn document_version(&self) -> ::std::option::Option<&str> {
        self.document_version.as_deref()
    }
    /// <p>The change template review details to update.</p>
    pub fn document_reviews(&self) -> ::std::option::Option<&crate::types::DocumentReviews> {
        self.document_reviews.as_ref()
    }
}
impl UpdateDocumentMetadataInput {
    /// Creates a new builder-style object to manufacture [`UpdateDocumentMetadataInput`](crate::operation::update_document_metadata::UpdateDocumentMetadataInput).
    pub fn builder() -> crate::operation::update_document_metadata::builders::UpdateDocumentMetadataInputBuilder {
        crate::operation::update_document_metadata::builders::UpdateDocumentMetadataInputBuilder::default()
    }
}

/// A builder for [`UpdateDocumentMetadataInput`](crate::operation::update_document_metadata::UpdateDocumentMetadataInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateDocumentMetadataInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) document_version: ::std::option::Option<::std::string::String>,
    pub(crate) document_reviews: ::std::option::Option<crate::types::DocumentReviews>,
}
impl UpdateDocumentMetadataInputBuilder {
    /// <p>The name of the change template for which a version's metadata is to be updated.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the change template for which a version's metadata is to be updated.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the change template for which a version's metadata is to be updated.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The version of a change template in which to update approval metadata.</p>
    pub fn document_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.document_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of a change template in which to update approval metadata.</p>
    pub fn set_document_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.document_version = input;
        self
    }
    /// <p>The version of a change template in which to update approval metadata.</p>
    pub fn get_document_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.document_version
    }
    /// <p>The change template review details to update.</p>
    /// This field is required.
    pub fn document_reviews(mut self, input: crate::types::DocumentReviews) -> Self {
        self.document_reviews = ::std::option::Option::Some(input);
        self
    }
    /// <p>The change template review details to update.</p>
    pub fn set_document_reviews(mut self, input: ::std::option::Option<crate::types::DocumentReviews>) -> Self {
        self.document_reviews = input;
        self
    }
    /// <p>The change template review details to update.</p>
    pub fn get_document_reviews(&self) -> &::std::option::Option<crate::types::DocumentReviews> {
        &self.document_reviews
    }
    /// Consumes the builder and constructs a [`UpdateDocumentMetadataInput`](crate::operation::update_document_metadata::UpdateDocumentMetadataInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_document_metadata::UpdateDocumentMetadataInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_document_metadata::UpdateDocumentMetadataInput {
            name: self.name,
            document_version: self.document_version,
            document_reviews: self.document_reviews,
        })
    }
}
