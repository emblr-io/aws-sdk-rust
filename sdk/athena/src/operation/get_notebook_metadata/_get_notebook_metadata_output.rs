// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetNotebookMetadataOutput {
    /// <p>The metadata that is returned for the specified notebook ID.</p>
    pub notebook_metadata: ::std::option::Option<crate::types::NotebookMetadata>,
    _request_id: Option<String>,
}
impl GetNotebookMetadataOutput {
    /// <p>The metadata that is returned for the specified notebook ID.</p>
    pub fn notebook_metadata(&self) -> ::std::option::Option<&crate::types::NotebookMetadata> {
        self.notebook_metadata.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetNotebookMetadataOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetNotebookMetadataOutput {
    /// Creates a new builder-style object to manufacture [`GetNotebookMetadataOutput`](crate::operation::get_notebook_metadata::GetNotebookMetadataOutput).
    pub fn builder() -> crate::operation::get_notebook_metadata::builders::GetNotebookMetadataOutputBuilder {
        crate::operation::get_notebook_metadata::builders::GetNotebookMetadataOutputBuilder::default()
    }
}

/// A builder for [`GetNotebookMetadataOutput`](crate::operation::get_notebook_metadata::GetNotebookMetadataOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetNotebookMetadataOutputBuilder {
    pub(crate) notebook_metadata: ::std::option::Option<crate::types::NotebookMetadata>,
    _request_id: Option<String>,
}
impl GetNotebookMetadataOutputBuilder {
    /// <p>The metadata that is returned for the specified notebook ID.</p>
    pub fn notebook_metadata(mut self, input: crate::types::NotebookMetadata) -> Self {
        self.notebook_metadata = ::std::option::Option::Some(input);
        self
    }
    /// <p>The metadata that is returned for the specified notebook ID.</p>
    pub fn set_notebook_metadata(mut self, input: ::std::option::Option<crate::types::NotebookMetadata>) -> Self {
        self.notebook_metadata = input;
        self
    }
    /// <p>The metadata that is returned for the specified notebook ID.</p>
    pub fn get_notebook_metadata(&self) -> &::std::option::Option<crate::types::NotebookMetadata> {
        &self.notebook_metadata
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetNotebookMetadataOutput`](crate::operation::get_notebook_metadata::GetNotebookMetadataOutput).
    pub fn build(self) -> crate::operation::get_notebook_metadata::GetNotebookMetadataOutput {
        crate::operation::get_notebook_metadata::GetNotebookMetadataOutput {
            notebook_metadata: self.notebook_metadata,
            _request_id: self._request_id,
        }
    }
}
