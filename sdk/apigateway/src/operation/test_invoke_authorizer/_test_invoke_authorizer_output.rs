// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the response of the test invoke request for a custom Authorizer</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TestInvokeAuthorizerOutput {
    /// <p>The HTTP status code that the client would have received. Value is 0 if the authorizer succeeded.</p>
    pub client_status: i32,
    /// <p>The API Gateway execution log for the test authorizer request.</p>
    pub log: ::std::option::Option<::std::string::String>,
    /// <p>The execution latency, in ms, of the test authorizer request.</p>
    pub latency: i64,
    /// <p>The principal identity returned by the Authorizer</p>
    pub principal_id: ::std::option::Option<::std::string::String>,
    /// <p>The JSON policy document returned by the Authorizer</p>
    pub policy: ::std::option::Option<::std::string::String>,
    /// <p>The authorization response.</p>
    pub authorization: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>>,
    /// <p>The open identity claims, with any supported custom attributes, returned from the Cognito Your User Pool configured for the API.</p>
    pub claims: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl TestInvokeAuthorizerOutput {
    /// <p>The HTTP status code that the client would have received. Value is 0 if the authorizer succeeded.</p>
    pub fn client_status(&self) -> i32 {
        self.client_status
    }
    /// <p>The API Gateway execution log for the test authorizer request.</p>
    pub fn log(&self) -> ::std::option::Option<&str> {
        self.log.as_deref()
    }
    /// <p>The execution latency, in ms, of the test authorizer request.</p>
    pub fn latency(&self) -> i64 {
        self.latency
    }
    /// <p>The principal identity returned by the Authorizer</p>
    pub fn principal_id(&self) -> ::std::option::Option<&str> {
        self.principal_id.as_deref()
    }
    /// <p>The JSON policy document returned by the Authorizer</p>
    pub fn policy(&self) -> ::std::option::Option<&str> {
        self.policy.as_deref()
    }
    /// <p>The authorization response.</p>
    pub fn authorization(
        &self,
    ) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>> {
        self.authorization.as_ref()
    }
    /// <p>The open identity claims, with any supported custom attributes, returned from the Cognito Your User Pool configured for the API.</p>
    pub fn claims(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.claims.as_ref()
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
    pub(crate) client_status: ::std::option::Option<i32>,
    pub(crate) log: ::std::option::Option<::std::string::String>,
    pub(crate) latency: ::std::option::Option<i64>,
    pub(crate) principal_id: ::std::option::Option<::std::string::String>,
    pub(crate) policy: ::std::option::Option<::std::string::String>,
    pub(crate) authorization: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>>,
    pub(crate) claims: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl TestInvokeAuthorizerOutputBuilder {
    /// <p>The HTTP status code that the client would have received. Value is 0 if the authorizer succeeded.</p>
    pub fn client_status(mut self, input: i32) -> Self {
        self.client_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The HTTP status code that the client would have received. Value is 0 if the authorizer succeeded.</p>
    pub fn set_client_status(mut self, input: ::std::option::Option<i32>) -> Self {
        self.client_status = input;
        self
    }
    /// <p>The HTTP status code that the client would have received. Value is 0 if the authorizer succeeded.</p>
    pub fn get_client_status(&self) -> &::std::option::Option<i32> {
        &self.client_status
    }
    /// <p>The API Gateway execution log for the test authorizer request.</p>
    pub fn log(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.log = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The API Gateway execution log for the test authorizer request.</p>
    pub fn set_log(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.log = input;
        self
    }
    /// <p>The API Gateway execution log for the test authorizer request.</p>
    pub fn get_log(&self) -> &::std::option::Option<::std::string::String> {
        &self.log
    }
    /// <p>The execution latency, in ms, of the test authorizer request.</p>
    pub fn latency(mut self, input: i64) -> Self {
        self.latency = ::std::option::Option::Some(input);
        self
    }
    /// <p>The execution latency, in ms, of the test authorizer request.</p>
    pub fn set_latency(mut self, input: ::std::option::Option<i64>) -> Self {
        self.latency = input;
        self
    }
    /// <p>The execution latency, in ms, of the test authorizer request.</p>
    pub fn get_latency(&self) -> &::std::option::Option<i64> {
        &self.latency
    }
    /// <p>The principal identity returned by the Authorizer</p>
    pub fn principal_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.principal_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The principal identity returned by the Authorizer</p>
    pub fn set_principal_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.principal_id = input;
        self
    }
    /// <p>The principal identity returned by the Authorizer</p>
    pub fn get_principal_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.principal_id
    }
    /// <p>The JSON policy document returned by the Authorizer</p>
    pub fn policy(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The JSON policy document returned by the Authorizer</p>
    pub fn set_policy(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy = input;
        self
    }
    /// <p>The JSON policy document returned by the Authorizer</p>
    pub fn get_policy(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy
    }
    /// Adds a key-value pair to `authorization`.
    ///
    /// To override the contents of this collection use [`set_authorization`](Self::set_authorization).
    ///
    /// <p>The authorization response.</p>
    pub fn authorization(mut self, k: impl ::std::convert::Into<::std::string::String>, v: ::std::vec::Vec<::std::string::String>) -> Self {
        let mut hash_map = self.authorization.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.authorization = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The authorization response.</p>
    pub fn set_authorization(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>>,
    ) -> Self {
        self.authorization = input;
        self
    }
    /// <p>The authorization response.</p>
    pub fn get_authorization(
        &self,
    ) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>> {
        &self.authorization
    }
    /// Adds a key-value pair to `claims`.
    ///
    /// To override the contents of this collection use [`set_claims`](Self::set_claims).
    ///
    /// <p>The open identity claims, with any supported custom attributes, returned from the Cognito Your User Pool configured for the API.</p>
    pub fn claims(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.claims.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.claims = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The open identity claims, with any supported custom attributes, returned from the Cognito Your User Pool configured for the API.</p>
    pub fn set_claims(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.claims = input;
        self
    }
    /// <p>The open identity claims, with any supported custom attributes, returned from the Cognito Your User Pool configured for the API.</p>
    pub fn get_claims(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.claims
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
            client_status: self.client_status.unwrap_or_default(),
            log: self.log,
            latency: self.latency.unwrap_or_default(),
            principal_id: self.principal_id,
            policy: self.policy,
            authorization: self.authorization,
            claims: self.claims,
            _request_id: self._request_id,
        }
    }
}
