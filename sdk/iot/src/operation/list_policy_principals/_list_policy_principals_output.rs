// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The output from the ListPolicyPrincipals operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListPolicyPrincipalsOutput {
    /// <p>The descriptions of the principals.</p>
    pub principals: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The marker for the next set of results, or null if there are no additional results.</p>
    pub next_marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListPolicyPrincipalsOutput {
    /// <p>The descriptions of the principals.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.principals.is_none()`.
    pub fn principals(&self) -> &[::std::string::String] {
        self.principals.as_deref().unwrap_or_default()
    }
    /// <p>The marker for the next set of results, or null if there are no additional results.</p>
    pub fn next_marker(&self) -> ::std::option::Option<&str> {
        self.next_marker.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListPolicyPrincipalsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListPolicyPrincipalsOutput {
    /// Creates a new builder-style object to manufacture [`ListPolicyPrincipalsOutput`](crate::operation::list_policy_principals::ListPolicyPrincipalsOutput).
    pub fn builder() -> crate::operation::list_policy_principals::builders::ListPolicyPrincipalsOutputBuilder {
        crate::operation::list_policy_principals::builders::ListPolicyPrincipalsOutputBuilder::default()
    }
}

/// A builder for [`ListPolicyPrincipalsOutput`](crate::operation::list_policy_principals::ListPolicyPrincipalsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListPolicyPrincipalsOutputBuilder {
    pub(crate) principals: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) next_marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListPolicyPrincipalsOutputBuilder {
    /// Appends an item to `principals`.
    ///
    /// To override the contents of this collection use [`set_principals`](Self::set_principals).
    ///
    /// <p>The descriptions of the principals.</p>
    pub fn principals(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.principals.unwrap_or_default();
        v.push(input.into());
        self.principals = ::std::option::Option::Some(v);
        self
    }
    /// <p>The descriptions of the principals.</p>
    pub fn set_principals(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.principals = input;
        self
    }
    /// <p>The descriptions of the principals.</p>
    pub fn get_principals(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.principals
    }
    /// <p>The marker for the next set of results, or null if there are no additional results.</p>
    pub fn next_marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The marker for the next set of results, or null if there are no additional results.</p>
    pub fn set_next_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_marker = input;
        self
    }
    /// <p>The marker for the next set of results, or null if there are no additional results.</p>
    pub fn get_next_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_marker
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListPolicyPrincipalsOutput`](crate::operation::list_policy_principals::ListPolicyPrincipalsOutput).
    pub fn build(self) -> crate::operation::list_policy_principals::ListPolicyPrincipalsOutput {
        crate::operation::list_policy_principals::ListPolicyPrincipalsOutput {
            principals: self.principals,
            next_marker: self.next_marker,
            _request_id: self._request_id,
        }
    }
}
