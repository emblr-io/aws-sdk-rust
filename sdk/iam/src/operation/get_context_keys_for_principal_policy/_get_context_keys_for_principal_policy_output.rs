// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the response to a successful <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetContextKeysForPrincipalPolicy.html">GetContextKeysForPrincipalPolicy</a> or <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetContextKeysForCustomPolicy.html">GetContextKeysForCustomPolicy</a> request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetContextKeysForPrincipalPolicyOutput {
    /// <p>The list of context keys that are referenced in the input policies.</p>
    pub context_key_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    _request_id: Option<String>,
}
impl GetContextKeysForPrincipalPolicyOutput {
    /// <p>The list of context keys that are referenced in the input policies.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.context_key_names.is_none()`.
    pub fn context_key_names(&self) -> &[::std::string::String] {
        self.context_key_names.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for GetContextKeysForPrincipalPolicyOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetContextKeysForPrincipalPolicyOutput {
    /// Creates a new builder-style object to manufacture [`GetContextKeysForPrincipalPolicyOutput`](crate::operation::get_context_keys_for_principal_policy::GetContextKeysForPrincipalPolicyOutput).
    pub fn builder() -> crate::operation::get_context_keys_for_principal_policy::builders::GetContextKeysForPrincipalPolicyOutputBuilder {
        crate::operation::get_context_keys_for_principal_policy::builders::GetContextKeysForPrincipalPolicyOutputBuilder::default()
    }
}

/// A builder for [`GetContextKeysForPrincipalPolicyOutput`](crate::operation::get_context_keys_for_principal_policy::GetContextKeysForPrincipalPolicyOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetContextKeysForPrincipalPolicyOutputBuilder {
    pub(crate) context_key_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    _request_id: Option<String>,
}
impl GetContextKeysForPrincipalPolicyOutputBuilder {
    /// Appends an item to `context_key_names`.
    ///
    /// To override the contents of this collection use [`set_context_key_names`](Self::set_context_key_names).
    ///
    /// <p>The list of context keys that are referenced in the input policies.</p>
    pub fn context_key_names(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.context_key_names.unwrap_or_default();
        v.push(input.into());
        self.context_key_names = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of context keys that are referenced in the input policies.</p>
    pub fn set_context_key_names(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.context_key_names = input;
        self
    }
    /// <p>The list of context keys that are referenced in the input policies.</p>
    pub fn get_context_key_names(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.context_key_names
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetContextKeysForPrincipalPolicyOutput`](crate::operation::get_context_keys_for_principal_policy::GetContextKeysForPrincipalPolicyOutput).
    pub fn build(self) -> crate::operation::get_context_keys_for_principal_policy::GetContextKeysForPrincipalPolicyOutput {
        crate::operation::get_context_keys_for_principal_policy::GetContextKeysForPrincipalPolicyOutput {
            context_key_names: self.context_key_names,
            _request_id: self._request_id,
        }
    }
}
