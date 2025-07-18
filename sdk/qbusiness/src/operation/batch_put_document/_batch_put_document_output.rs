// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchPutDocumentOutput {
    /// <p>A list of documents that were not added to the Amazon Q Business index because the document failed a validation check. Each document contains an error message that indicates why the document couldn't be added to the index.</p>
    pub failed_documents: ::std::option::Option<::std::vec::Vec<crate::types::FailedDocument>>,
    _request_id: Option<String>,
}
impl BatchPutDocumentOutput {
    /// <p>A list of documents that were not added to the Amazon Q Business index because the document failed a validation check. Each document contains an error message that indicates why the document couldn't be added to the index.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.failed_documents.is_none()`.
    pub fn failed_documents(&self) -> &[crate::types::FailedDocument] {
        self.failed_documents.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for BatchPutDocumentOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl BatchPutDocumentOutput {
    /// Creates a new builder-style object to manufacture [`BatchPutDocumentOutput`](crate::operation::batch_put_document::BatchPutDocumentOutput).
    pub fn builder() -> crate::operation::batch_put_document::builders::BatchPutDocumentOutputBuilder {
        crate::operation::batch_put_document::builders::BatchPutDocumentOutputBuilder::default()
    }
}

/// A builder for [`BatchPutDocumentOutput`](crate::operation::batch_put_document::BatchPutDocumentOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchPutDocumentOutputBuilder {
    pub(crate) failed_documents: ::std::option::Option<::std::vec::Vec<crate::types::FailedDocument>>,
    _request_id: Option<String>,
}
impl BatchPutDocumentOutputBuilder {
    /// Appends an item to `failed_documents`.
    ///
    /// To override the contents of this collection use [`set_failed_documents`](Self::set_failed_documents).
    ///
    /// <p>A list of documents that were not added to the Amazon Q Business index because the document failed a validation check. Each document contains an error message that indicates why the document couldn't be added to the index.</p>
    pub fn failed_documents(mut self, input: crate::types::FailedDocument) -> Self {
        let mut v = self.failed_documents.unwrap_or_default();
        v.push(input);
        self.failed_documents = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of documents that were not added to the Amazon Q Business index because the document failed a validation check. Each document contains an error message that indicates why the document couldn't be added to the index.</p>
    pub fn set_failed_documents(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::FailedDocument>>) -> Self {
        self.failed_documents = input;
        self
    }
    /// <p>A list of documents that were not added to the Amazon Q Business index because the document failed a validation check. Each document contains an error message that indicates why the document couldn't be added to the index.</p>
    pub fn get_failed_documents(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::FailedDocument>> {
        &self.failed_documents
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`BatchPutDocumentOutput`](crate::operation::batch_put_document::BatchPutDocumentOutput).
    pub fn build(self) -> crate::operation::batch_put_document::BatchPutDocumentOutput {
        crate::operation::batch_put_document::BatchPutDocumentOutput {
            failed_documents: self.failed_documents,
            _request_id: self._request_id,
        }
    }
}
