// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetResourcePoliciesOutput {
    /// <p>An array of resource policy documents in JSON format.</p>
    pub policies: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>If present, this value indicates that more output is available than is included in the current response. Use this value in the <code>NextToken</code> request parameter in a subsequent call to the operation to get the next part of the output. You should repeat this until the <code>NextToken</code> response element comes back as <code>null</code>. This indicates that this is the last page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetResourcePoliciesOutput {
    /// <p>An array of resource policy documents in JSON format.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.policies.is_none()`.
    pub fn policies(&self) -> &[::std::string::String] {
        self.policies.as_deref().unwrap_or_default()
    }
    /// <p>If present, this value indicates that more output is available than is included in the current response. Use this value in the <code>NextToken</code> request parameter in a subsequent call to the operation to get the next part of the output. You should repeat this until the <code>NextToken</code> response element comes back as <code>null</code>. This indicates that this is the last page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetResourcePoliciesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetResourcePoliciesOutput {
    /// Creates a new builder-style object to manufacture [`GetResourcePoliciesOutput`](crate::operation::get_resource_policies::GetResourcePoliciesOutput).
    pub fn builder() -> crate::operation::get_resource_policies::builders::GetResourcePoliciesOutputBuilder {
        crate::operation::get_resource_policies::builders::GetResourcePoliciesOutputBuilder::default()
    }
}

/// A builder for [`GetResourcePoliciesOutput`](crate::operation::get_resource_policies::GetResourcePoliciesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetResourcePoliciesOutputBuilder {
    pub(crate) policies: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetResourcePoliciesOutputBuilder {
    /// Appends an item to `policies`.
    ///
    /// To override the contents of this collection use [`set_policies`](Self::set_policies).
    ///
    /// <p>An array of resource policy documents in JSON format.</p>
    pub fn policies(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.policies.unwrap_or_default();
        v.push(input.into());
        self.policies = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of resource policy documents in JSON format.</p>
    pub fn set_policies(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.policies = input;
        self
    }
    /// <p>An array of resource policy documents in JSON format.</p>
    pub fn get_policies(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.policies
    }
    /// <p>If present, this value indicates that more output is available than is included in the current response. Use this value in the <code>NextToken</code> request parameter in a subsequent call to the operation to get the next part of the output. You should repeat this until the <code>NextToken</code> response element comes back as <code>null</code>. This indicates that this is the last page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If present, this value indicates that more output is available than is included in the current response. Use this value in the <code>NextToken</code> request parameter in a subsequent call to the operation to get the next part of the output. You should repeat this until the <code>NextToken</code> response element comes back as <code>null</code>. This indicates that this is the last page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If present, this value indicates that more output is available than is included in the current response. Use this value in the <code>NextToken</code> request parameter in a subsequent call to the operation to get the next part of the output. You should repeat this until the <code>NextToken</code> response element comes back as <code>null</code>. This indicates that this is the last page of results.</p>
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
    /// Consumes the builder and constructs a [`GetResourcePoliciesOutput`](crate::operation::get_resource_policies::GetResourcePoliciesOutput).
    pub fn build(self) -> crate::operation::get_resource_policies::GetResourcePoliciesOutput {
        crate::operation::get_resource_policies::GetResourcePoliciesOutput {
            policies: self.policies,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
