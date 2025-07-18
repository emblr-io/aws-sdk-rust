// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListTargetResourceTypesOutput {
    /// <p>The target resource types.</p>
    pub target_resource_types: ::std::option::Option<::std::vec::Vec<crate::types::TargetResourceTypeSummary>>,
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListTargetResourceTypesOutput {
    /// <p>The target resource types.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.target_resource_types.is_none()`.
    pub fn target_resource_types(&self) -> &[crate::types::TargetResourceTypeSummary] {
        self.target_resource_types.as_deref().unwrap_or_default()
    }
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListTargetResourceTypesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListTargetResourceTypesOutput {
    /// Creates a new builder-style object to manufacture [`ListTargetResourceTypesOutput`](crate::operation::list_target_resource_types::ListTargetResourceTypesOutput).
    pub fn builder() -> crate::operation::list_target_resource_types::builders::ListTargetResourceTypesOutputBuilder {
        crate::operation::list_target_resource_types::builders::ListTargetResourceTypesOutputBuilder::default()
    }
}

/// A builder for [`ListTargetResourceTypesOutput`](crate::operation::list_target_resource_types::ListTargetResourceTypesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListTargetResourceTypesOutputBuilder {
    pub(crate) target_resource_types: ::std::option::Option<::std::vec::Vec<crate::types::TargetResourceTypeSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListTargetResourceTypesOutputBuilder {
    /// Appends an item to `target_resource_types`.
    ///
    /// To override the contents of this collection use [`set_target_resource_types`](Self::set_target_resource_types).
    ///
    /// <p>The target resource types.</p>
    pub fn target_resource_types(mut self, input: crate::types::TargetResourceTypeSummary) -> Self {
        let mut v = self.target_resource_types.unwrap_or_default();
        v.push(input);
        self.target_resource_types = ::std::option::Option::Some(v);
        self
    }
    /// <p>The target resource types.</p>
    pub fn set_target_resource_types(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::TargetResourceTypeSummary>>) -> Self {
        self.target_resource_types = input;
        self
    }
    /// <p>The target resource types.</p>
    pub fn get_target_resource_types(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::TargetResourceTypeSummary>> {
        &self.target_resource_types
    }
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
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
    /// Consumes the builder and constructs a [`ListTargetResourceTypesOutput`](crate::operation::list_target_resource_types::ListTargetResourceTypesOutput).
    pub fn build(self) -> crate::operation::list_target_resource_types::ListTargetResourceTypesOutput {
        crate::operation::list_target_resource_types::ListTargetResourceTypesOutput {
            target_resource_types: self.target_resource_types,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
