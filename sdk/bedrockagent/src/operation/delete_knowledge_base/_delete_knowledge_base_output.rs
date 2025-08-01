// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteKnowledgeBaseOutput {
    /// <p>The unique identifier of the knowledge base that was deleted.</p>
    pub knowledge_base_id: ::std::string::String,
    /// <p>The status of the knowledge base and whether it has been successfully deleted.</p>
    pub status: crate::types::KnowledgeBaseStatus,
    _request_id: Option<String>,
}
impl DeleteKnowledgeBaseOutput {
    /// <p>The unique identifier of the knowledge base that was deleted.</p>
    pub fn knowledge_base_id(&self) -> &str {
        use std::ops::Deref;
        self.knowledge_base_id.deref()
    }
    /// <p>The status of the knowledge base and whether it has been successfully deleted.</p>
    pub fn status(&self) -> &crate::types::KnowledgeBaseStatus {
        &self.status
    }
}
impl ::aws_types::request_id::RequestId for DeleteKnowledgeBaseOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteKnowledgeBaseOutput {
    /// Creates a new builder-style object to manufacture [`DeleteKnowledgeBaseOutput`](crate::operation::delete_knowledge_base::DeleteKnowledgeBaseOutput).
    pub fn builder() -> crate::operation::delete_knowledge_base::builders::DeleteKnowledgeBaseOutputBuilder {
        crate::operation::delete_knowledge_base::builders::DeleteKnowledgeBaseOutputBuilder::default()
    }
}

/// A builder for [`DeleteKnowledgeBaseOutput`](crate::operation::delete_knowledge_base::DeleteKnowledgeBaseOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteKnowledgeBaseOutputBuilder {
    pub(crate) knowledge_base_id: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::KnowledgeBaseStatus>,
    _request_id: Option<String>,
}
impl DeleteKnowledgeBaseOutputBuilder {
    /// <p>The unique identifier of the knowledge base that was deleted.</p>
    /// This field is required.
    pub fn knowledge_base_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.knowledge_base_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the knowledge base that was deleted.</p>
    pub fn set_knowledge_base_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.knowledge_base_id = input;
        self
    }
    /// <p>The unique identifier of the knowledge base that was deleted.</p>
    pub fn get_knowledge_base_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.knowledge_base_id
    }
    /// <p>The status of the knowledge base and whether it has been successfully deleted.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::KnowledgeBaseStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the knowledge base and whether it has been successfully deleted.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::KnowledgeBaseStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the knowledge base and whether it has been successfully deleted.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::KnowledgeBaseStatus> {
        &self.status
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteKnowledgeBaseOutput`](crate::operation::delete_knowledge_base::DeleteKnowledgeBaseOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`knowledge_base_id`](crate::operation::delete_knowledge_base::builders::DeleteKnowledgeBaseOutputBuilder::knowledge_base_id)
    /// - [`status`](crate::operation::delete_knowledge_base::builders::DeleteKnowledgeBaseOutputBuilder::status)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_knowledge_base::DeleteKnowledgeBaseOutput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::delete_knowledge_base::DeleteKnowledgeBaseOutput {
            knowledge_base_id: self.knowledge_base_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "knowledge_base_id",
                    "knowledge_base_id was not specified but it is required when building DeleteKnowledgeBaseOutput",
                )
            })?,
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building DeleteKnowledgeBaseOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
