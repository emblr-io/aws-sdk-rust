// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SearchResourcesOutput {
    /// <p>The ARNs and resource types of resources that are members of the group that you specified.</p>
    pub resource_identifiers: ::std::option::Option<::std::vec::Vec<crate::types::ResourceIdentifier>>,
    /// <p>If present, indicates that more output is available than is included in the current response. Use this value in the <code>NextToken</code> request parameter in a subsequent call to the operation to get the next part of the output. You should repeat this until the <code>NextToken</code> response element comes back as <code>null</code>.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>A list of <code>QueryError</code> objects. Each error contains an <code>ErrorCode</code> and <code>Message</code>.</p>
    /// <p>Possible values for <code>ErrorCode</code>:</p>
    /// <ul>
    /// <li>
    /// <p><code>CLOUDFORMATION_STACK_INACTIVE</code></p></li>
    /// <li>
    /// <p><code>CLOUDFORMATION_STACK_NOT_EXISTING</code></p></li>
    /// <li>
    /// <p><code>CLOUDFORMATION_STACK_UNASSUMABLE_ROLE </code></p></li>
    /// </ul>
    pub query_errors: ::std::option::Option<::std::vec::Vec<crate::types::QueryError>>,
    _request_id: Option<String>,
}
impl SearchResourcesOutput {
    /// <p>The ARNs and resource types of resources that are members of the group that you specified.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.resource_identifiers.is_none()`.
    pub fn resource_identifiers(&self) -> &[crate::types::ResourceIdentifier] {
        self.resource_identifiers.as_deref().unwrap_or_default()
    }
    /// <p>If present, indicates that more output is available than is included in the current response. Use this value in the <code>NextToken</code> request parameter in a subsequent call to the operation to get the next part of the output. You should repeat this until the <code>NextToken</code> response element comes back as <code>null</code>.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>A list of <code>QueryError</code> objects. Each error contains an <code>ErrorCode</code> and <code>Message</code>.</p>
    /// <p>Possible values for <code>ErrorCode</code>:</p>
    /// <ul>
    /// <li>
    /// <p><code>CLOUDFORMATION_STACK_INACTIVE</code></p></li>
    /// <li>
    /// <p><code>CLOUDFORMATION_STACK_NOT_EXISTING</code></p></li>
    /// <li>
    /// <p><code>CLOUDFORMATION_STACK_UNASSUMABLE_ROLE </code></p></li>
    /// </ul>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.query_errors.is_none()`.
    pub fn query_errors(&self) -> &[crate::types::QueryError] {
        self.query_errors.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for SearchResourcesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl SearchResourcesOutput {
    /// Creates a new builder-style object to manufacture [`SearchResourcesOutput`](crate::operation::search_resources::SearchResourcesOutput).
    pub fn builder() -> crate::operation::search_resources::builders::SearchResourcesOutputBuilder {
        crate::operation::search_resources::builders::SearchResourcesOutputBuilder::default()
    }
}

/// A builder for [`SearchResourcesOutput`](crate::operation::search_resources::SearchResourcesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SearchResourcesOutputBuilder {
    pub(crate) resource_identifiers: ::std::option::Option<::std::vec::Vec<crate::types::ResourceIdentifier>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) query_errors: ::std::option::Option<::std::vec::Vec<crate::types::QueryError>>,
    _request_id: Option<String>,
}
impl SearchResourcesOutputBuilder {
    /// Appends an item to `resource_identifiers`.
    ///
    /// To override the contents of this collection use [`set_resource_identifiers`](Self::set_resource_identifiers).
    ///
    /// <p>The ARNs and resource types of resources that are members of the group that you specified.</p>
    pub fn resource_identifiers(mut self, input: crate::types::ResourceIdentifier) -> Self {
        let mut v = self.resource_identifiers.unwrap_or_default();
        v.push(input);
        self.resource_identifiers = ::std::option::Option::Some(v);
        self
    }
    /// <p>The ARNs and resource types of resources that are members of the group that you specified.</p>
    pub fn set_resource_identifiers(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ResourceIdentifier>>) -> Self {
        self.resource_identifiers = input;
        self
    }
    /// <p>The ARNs and resource types of resources that are members of the group that you specified.</p>
    pub fn get_resource_identifiers(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ResourceIdentifier>> {
        &self.resource_identifiers
    }
    /// <p>If present, indicates that more output is available than is included in the current response. Use this value in the <code>NextToken</code> request parameter in a subsequent call to the operation to get the next part of the output. You should repeat this until the <code>NextToken</code> response element comes back as <code>null</code>.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If present, indicates that more output is available than is included in the current response. Use this value in the <code>NextToken</code> request parameter in a subsequent call to the operation to get the next part of the output. You should repeat this until the <code>NextToken</code> response element comes back as <code>null</code>.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If present, indicates that more output is available than is included in the current response. Use this value in the <code>NextToken</code> request parameter in a subsequent call to the operation to get the next part of the output. You should repeat this until the <code>NextToken</code> response element comes back as <code>null</code>.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `query_errors`.
    ///
    /// To override the contents of this collection use [`set_query_errors`](Self::set_query_errors).
    ///
    /// <p>A list of <code>QueryError</code> objects. Each error contains an <code>ErrorCode</code> and <code>Message</code>.</p>
    /// <p>Possible values for <code>ErrorCode</code>:</p>
    /// <ul>
    /// <li>
    /// <p><code>CLOUDFORMATION_STACK_INACTIVE</code></p></li>
    /// <li>
    /// <p><code>CLOUDFORMATION_STACK_NOT_EXISTING</code></p></li>
    /// <li>
    /// <p><code>CLOUDFORMATION_STACK_UNASSUMABLE_ROLE </code></p></li>
    /// </ul>
    pub fn query_errors(mut self, input: crate::types::QueryError) -> Self {
        let mut v = self.query_errors.unwrap_or_default();
        v.push(input);
        self.query_errors = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of <code>QueryError</code> objects. Each error contains an <code>ErrorCode</code> and <code>Message</code>.</p>
    /// <p>Possible values for <code>ErrorCode</code>:</p>
    /// <ul>
    /// <li>
    /// <p><code>CLOUDFORMATION_STACK_INACTIVE</code></p></li>
    /// <li>
    /// <p><code>CLOUDFORMATION_STACK_NOT_EXISTING</code></p></li>
    /// <li>
    /// <p><code>CLOUDFORMATION_STACK_UNASSUMABLE_ROLE </code></p></li>
    /// </ul>
    pub fn set_query_errors(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::QueryError>>) -> Self {
        self.query_errors = input;
        self
    }
    /// <p>A list of <code>QueryError</code> objects. Each error contains an <code>ErrorCode</code> and <code>Message</code>.</p>
    /// <p>Possible values for <code>ErrorCode</code>:</p>
    /// <ul>
    /// <li>
    /// <p><code>CLOUDFORMATION_STACK_INACTIVE</code></p></li>
    /// <li>
    /// <p><code>CLOUDFORMATION_STACK_NOT_EXISTING</code></p></li>
    /// <li>
    /// <p><code>CLOUDFORMATION_STACK_UNASSUMABLE_ROLE </code></p></li>
    /// </ul>
    pub fn get_query_errors(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::QueryError>> {
        &self.query_errors
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`SearchResourcesOutput`](crate::operation::search_resources::SearchResourcesOutput).
    pub fn build(self) -> crate::operation::search_resources::SearchResourcesOutput {
        crate::operation::search_resources::SearchResourcesOutput {
            resource_identifiers: self.resource_identifiers,
            next_token: self.next_token,
            query_errors: self.query_errors,
            _request_id: self._request_id,
        }
    }
}
