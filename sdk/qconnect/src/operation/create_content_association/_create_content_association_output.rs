// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateContentAssociationOutput {
    /// <p>The association between Amazon Q in Connect content and another resource.</p>
    pub content_association: ::std::option::Option<crate::types::ContentAssociationData>,
    _request_id: Option<String>,
}
impl CreateContentAssociationOutput {
    /// <p>The association between Amazon Q in Connect content and another resource.</p>
    pub fn content_association(&self) -> ::std::option::Option<&crate::types::ContentAssociationData> {
        self.content_association.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateContentAssociationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateContentAssociationOutput {
    /// Creates a new builder-style object to manufacture [`CreateContentAssociationOutput`](crate::operation::create_content_association::CreateContentAssociationOutput).
    pub fn builder() -> crate::operation::create_content_association::builders::CreateContentAssociationOutputBuilder {
        crate::operation::create_content_association::builders::CreateContentAssociationOutputBuilder::default()
    }
}

/// A builder for [`CreateContentAssociationOutput`](crate::operation::create_content_association::CreateContentAssociationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateContentAssociationOutputBuilder {
    pub(crate) content_association: ::std::option::Option<crate::types::ContentAssociationData>,
    _request_id: Option<String>,
}
impl CreateContentAssociationOutputBuilder {
    /// <p>The association between Amazon Q in Connect content and another resource.</p>
    pub fn content_association(mut self, input: crate::types::ContentAssociationData) -> Self {
        self.content_association = ::std::option::Option::Some(input);
        self
    }
    /// <p>The association between Amazon Q in Connect content and another resource.</p>
    pub fn set_content_association(mut self, input: ::std::option::Option<crate::types::ContentAssociationData>) -> Self {
        self.content_association = input;
        self
    }
    /// <p>The association between Amazon Q in Connect content and another resource.</p>
    pub fn get_content_association(&self) -> &::std::option::Option<crate::types::ContentAssociationData> {
        &self.content_association
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateContentAssociationOutput`](crate::operation::create_content_association::CreateContentAssociationOutput).
    pub fn build(self) -> crate::operation::create_content_association::CreateContentAssociationOutput {
        crate::operation::create_content_association::CreateContentAssociationOutput {
            content_association: self.content_association,
            _request_id: self._request_id,
        }
    }
}
