// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListKnowledgeBaseDocumentsOutput {
    /// <p>A list of objects, each of which contains information about the documents that were retrieved.</p>
    pub document_details: ::std::vec::Vec<crate::types::KnowledgeBaseDocumentDetail>,
    /// <p>If the total number of results is greater than the <code>maxResults</code> value provided in the request, use this token when making another request in the <code>nextToken</code> field to return the next batch of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListKnowledgeBaseDocumentsOutput {
    /// <p>A list of objects, each of which contains information about the documents that were retrieved.</p>
    pub fn document_details(&self) -> &[crate::types::KnowledgeBaseDocumentDetail] {
        use std::ops::Deref;
        self.document_details.deref()
    }
    /// <p>If the total number of results is greater than the <code>maxResults</code> value provided in the request, use this token when making another request in the <code>nextToken</code> field to return the next batch of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListKnowledgeBaseDocumentsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListKnowledgeBaseDocumentsOutput {
    /// Creates a new builder-style object to manufacture [`ListKnowledgeBaseDocumentsOutput`](crate::operation::list_knowledge_base_documents::ListKnowledgeBaseDocumentsOutput).
    pub fn builder() -> crate::operation::list_knowledge_base_documents::builders::ListKnowledgeBaseDocumentsOutputBuilder {
        crate::operation::list_knowledge_base_documents::builders::ListKnowledgeBaseDocumentsOutputBuilder::default()
    }
}

/// A builder for [`ListKnowledgeBaseDocumentsOutput`](crate::operation::list_knowledge_base_documents::ListKnowledgeBaseDocumentsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListKnowledgeBaseDocumentsOutputBuilder {
    pub(crate) document_details: ::std::option::Option<::std::vec::Vec<crate::types::KnowledgeBaseDocumentDetail>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListKnowledgeBaseDocumentsOutputBuilder {
    /// Appends an item to `document_details`.
    ///
    /// To override the contents of this collection use [`set_document_details`](Self::set_document_details).
    ///
    /// <p>A list of objects, each of which contains information about the documents that were retrieved.</p>
    pub fn document_details(mut self, input: crate::types::KnowledgeBaseDocumentDetail) -> Self {
        let mut v = self.document_details.unwrap_or_default();
        v.push(input);
        self.document_details = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of objects, each of which contains information about the documents that were retrieved.</p>
    pub fn set_document_details(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::KnowledgeBaseDocumentDetail>>) -> Self {
        self.document_details = input;
        self
    }
    /// <p>A list of objects, each of which contains information about the documents that were retrieved.</p>
    pub fn get_document_details(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::KnowledgeBaseDocumentDetail>> {
        &self.document_details
    }
    /// <p>If the total number of results is greater than the <code>maxResults</code> value provided in the request, use this token when making another request in the <code>nextToken</code> field to return the next batch of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the total number of results is greater than the <code>maxResults</code> value provided in the request, use this token when making another request in the <code>nextToken</code> field to return the next batch of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If the total number of results is greater than the <code>maxResults</code> value provided in the request, use this token when making another request in the <code>nextToken</code> field to return the next batch of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListKnowledgeBaseDocumentsOutput`](crate::operation::list_knowledge_base_documents::ListKnowledgeBaseDocumentsOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`document_details`](crate::operation::list_knowledge_base_documents::builders::ListKnowledgeBaseDocumentsOutputBuilder::document_details)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_knowledge_base_documents::ListKnowledgeBaseDocumentsOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_knowledge_base_documents::ListKnowledgeBaseDocumentsOutput {
            document_details: self.document_details.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "document_details",
                    "document_details was not specified but it is required when building ListKnowledgeBaseDocumentsOutput",
                )
            })?,
            next_token: self.next_token,
            _request_id: self._request_id,
        })
    }
}
