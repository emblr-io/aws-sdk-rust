// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListRelatedResourcesForAuditFindingOutput {
    /// <p>The related resources.</p>
    pub related_resources: ::std::option::Option<::std::vec::Vec<crate::types::RelatedResource>>,
    /// <p>A token that can be used to retrieve the next set of results, or <code>null</code> for the first API call.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListRelatedResourcesForAuditFindingOutput {
    /// <p>The related resources.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.related_resources.is_none()`.
    pub fn related_resources(&self) -> &[crate::types::RelatedResource] {
        self.related_resources.as_deref().unwrap_or_default()
    }
    /// <p>A token that can be used to retrieve the next set of results, or <code>null</code> for the first API call.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListRelatedResourcesForAuditFindingOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListRelatedResourcesForAuditFindingOutput {
    /// Creates a new builder-style object to manufacture [`ListRelatedResourcesForAuditFindingOutput`](crate::operation::list_related_resources_for_audit_finding::ListRelatedResourcesForAuditFindingOutput).
    pub fn builder() -> crate::operation::list_related_resources_for_audit_finding::builders::ListRelatedResourcesForAuditFindingOutputBuilder {
        crate::operation::list_related_resources_for_audit_finding::builders::ListRelatedResourcesForAuditFindingOutputBuilder::default()
    }
}

/// A builder for [`ListRelatedResourcesForAuditFindingOutput`](crate::operation::list_related_resources_for_audit_finding::ListRelatedResourcesForAuditFindingOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListRelatedResourcesForAuditFindingOutputBuilder {
    pub(crate) related_resources: ::std::option::Option<::std::vec::Vec<crate::types::RelatedResource>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListRelatedResourcesForAuditFindingOutputBuilder {
    /// Appends an item to `related_resources`.
    ///
    /// To override the contents of this collection use [`set_related_resources`](Self::set_related_resources).
    ///
    /// <p>The related resources.</p>
    pub fn related_resources(mut self, input: crate::types::RelatedResource) -> Self {
        let mut v = self.related_resources.unwrap_or_default();
        v.push(input);
        self.related_resources = ::std::option::Option::Some(v);
        self
    }
    /// <p>The related resources.</p>
    pub fn set_related_resources(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::RelatedResource>>) -> Self {
        self.related_resources = input;
        self
    }
    /// <p>The related resources.</p>
    pub fn get_related_resources(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::RelatedResource>> {
        &self.related_resources
    }
    /// <p>A token that can be used to retrieve the next set of results, or <code>null</code> for the first API call.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token that can be used to retrieve the next set of results, or <code>null</code> for the first API call.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token that can be used to retrieve the next set of results, or <code>null</code> for the first API call.</p>
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
    /// Consumes the builder and constructs a [`ListRelatedResourcesForAuditFindingOutput`](crate::operation::list_related_resources_for_audit_finding::ListRelatedResourcesForAuditFindingOutput).
    pub fn build(self) -> crate::operation::list_related_resources_for_audit_finding::ListRelatedResourcesForAuditFindingOutput {
        crate::operation::list_related_resources_for_audit_finding::ListRelatedResourcesForAuditFindingOutput {
            related_resources: self.related_resources,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
