// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TestInvokeAuthorizerOutput {
    /// <p>True if the token is authenticated, otherwise false.</p>
    pub is_authenticated: ::std::option::Option<bool>,
    /// <p>The principal ID.</p>
    pub principal_id: ::std::option::Option<::std::string::String>,
    /// <p>IAM policy documents.</p>
    pub policy_documents: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The number of seconds after which the temporary credentials are refreshed.</p>
    pub refresh_after_in_seconds: ::std::option::Option<i32>,
    /// <p>The number of seconds after which the connection is terminated.</p>
    pub disconnect_after_in_seconds: ::std::option::Option<i32>,
    _request_id: Option<String>,
}
impl TestInvokeAuthorizerOutput {
    /// <p>True if the token is authenticated, otherwise false.</p>
    pub fn is_authenticated(&self) -> ::std::option::Option<bool> {
        self.is_authenticated
    }
    /// <p>The principal ID.</p>
    pub fn principal_id(&self) -> ::std::option::Option<&str> {
        self.principal_id.as_deref()
    }
    /// <p>IAM policy documents.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.policy_documents.is_none()`.
    pub fn policy_documents(&self) -> &[::std::string::String] {
        self.policy_documents.as_deref().unwrap_or_default()
    }
    /// <p>The number of seconds after which the temporary credentials are refreshed.</p>
    pub fn refresh_after_in_seconds(&self) -> ::std::option::Option<i32> {
        self.refresh_after_in_seconds
    }
    /// <p>The number of seconds after which the connection is terminated.</p>
    pub fn disconnect_after_in_seconds(&self) -> ::std::option::Option<i32> {
        self.disconnect_after_in_seconds
    }
}
impl ::aws_types::request_id::RequestId for TestInvokeAuthorizerOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl TestInvokeAuthorizerOutput {
    /// Creates a new builder-style object to manufacture [`TestInvokeAuthorizerOutput`](crate::operation::test_invoke_authorizer::TestInvokeAuthorizerOutput).
    pub fn builder() -> crate::operation::test_invoke_authorizer::builders::TestInvokeAuthorizerOutputBuilder {
        crate::operation::test_invoke_authorizer::builders::TestInvokeAuthorizerOutputBuilder::default()
    }
}

/// A builder for [`TestInvokeAuthorizerOutput`](crate::operation::test_invoke_authorizer::TestInvokeAuthorizerOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TestInvokeAuthorizerOutputBuilder {
    pub(crate) is_authenticated: ::std::option::Option<bool>,
    pub(crate) principal_id: ::std::option::Option<::std::string::String>,
    pub(crate) policy_documents: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) refresh_after_in_seconds: ::std::option::Option<i32>,
    pub(crate) disconnect_after_in_seconds: ::std::option::Option<i32>,
    _request_id: Option<String>,
}
impl TestInvokeAuthorizerOutputBuilder {
    /// <p>True if the token is authenticated, otherwise false.</p>
    pub fn is_authenticated(mut self, input: bool) -> Self {
        self.is_authenticated = ::std::option::Option::Some(input);
        self
    }
    /// <p>True if the token is authenticated, otherwise false.</p>
    pub fn set_is_authenticated(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_authenticated = input;
        self
    }
    /// <p>True if the token is authenticated, otherwise false.</p>
    pub fn get_is_authenticated(&self) -> &::std::option::Option<bool> {
        &self.is_authenticated
    }
    /// <p>The principal ID.</p>
    pub fn principal_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.principal_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The principal ID.</p>
    pub fn set_principal_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.principal_id = input;
        self
    }
    /// <p>The principal ID.</p>
    pub fn get_principal_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.principal_id
    }
    /// Appends an item to `policy_documents`.
    ///
    /// To override the contents of this collection use [`set_policy_documents`](Self::set_policy_documents).
    ///
    /// <p>IAM policy documents.</p>
    pub fn policy_documents(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.policy_documents.unwrap_or_default();
        v.push(input.into());
        self.policy_documents = ::std::option::Option::Some(v);
        self
    }
    /// <p>IAM policy documents.</p>
    pub fn set_policy_documents(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.policy_documents = input;
        self
    }
    /// <p>IAM policy documents.</p>
    pub fn get_policy_documents(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.policy_documents
    }
    /// <p>The number of seconds after which the temporary credentials are refreshed.</p>
    pub fn refresh_after_in_seconds(mut self, input: i32) -> Self {
        self.refresh_after_in_seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of seconds after which the temporary credentials are refreshed.</p>
    pub fn set_refresh_after_in_seconds(mut self, input: ::std::option::Option<i32>) -> Self {
        self.refresh_after_in_seconds = input;
        self
    }
    /// <p>The number of seconds after which the temporary credentials are refreshed.</p>
    pub fn get_refresh_after_in_seconds(&self) -> &::std::option::Option<i32> {
        &self.refresh_after_in_seconds
    }
    /// <p>The number of seconds after which the connection is terminated.</p>
    pub fn disconnect_after_in_seconds(mut self, input: i32) -> Self {
        self.disconnect_after_in_seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of seconds after which the connection is terminated.</p>
    pub fn set_disconnect_after_in_seconds(mut self, input: ::std::option::Option<i32>) -> Self {
        self.disconnect_after_in_seconds = input;
        self
    }
    /// <p>The number of seconds after which the connection is terminated.</p>
    pub fn get_disconnect_after_in_seconds(&self) -> &::std::option::Option<i32> {
        &self.disconnect_after_in_seconds
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`TestInvokeAuthorizerOutput`](crate::operation::test_invoke_authorizer::TestInvokeAuthorizerOutput).
    pub fn build(self) -> crate::operation::test_invoke_authorizer::TestInvokeAuthorizerOutput {
        crate::operation::test_invoke_authorizer::TestInvokeAuthorizerOutput {
            is_authenticated: self.is_authenticated,
            principal_id: self.principal_id,
            policy_documents: self.policy_documents,
            refresh_after_in_seconds: self.refresh_after_in_seconds,
            disconnect_after_in_seconds: self.disconnect_after_in_seconds,
            _request_id: self._request_id,
        }
    }
}
