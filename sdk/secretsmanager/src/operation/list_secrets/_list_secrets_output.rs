// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListSecretsOutput {
    /// <p>A list of the secrets in the account.</p>
    pub secret_list: ::std::option::Option<::std::vec::Vec<crate::types::SecretListEntry>>,
    /// <p>Secrets Manager includes this value if there's more output available than what is included in the current response. This can occur even when the response includes no values at all, such as when you ask for a filtered view of a long list. To get the next results, call <code>ListSecrets</code> again with this value.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListSecretsOutput {
    /// <p>A list of the secrets in the account.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.secret_list.is_none()`.
    pub fn secret_list(&self) -> &[crate::types::SecretListEntry] {
        self.secret_list.as_deref().unwrap_or_default()
    }
    /// <p>Secrets Manager includes this value if there's more output available than what is included in the current response. This can occur even when the response includes no values at all, such as when you ask for a filtered view of a long list. To get the next results, call <code>ListSecrets</code> again with this value.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListSecretsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListSecretsOutput {
    /// Creates a new builder-style object to manufacture [`ListSecretsOutput`](crate::operation::list_secrets::ListSecretsOutput).
    pub fn builder() -> crate::operation::list_secrets::builders::ListSecretsOutputBuilder {
        crate::operation::list_secrets::builders::ListSecretsOutputBuilder::default()
    }
}

/// A builder for [`ListSecretsOutput`](crate::operation::list_secrets::ListSecretsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListSecretsOutputBuilder {
    pub(crate) secret_list: ::std::option::Option<::std::vec::Vec<crate::types::SecretListEntry>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListSecretsOutputBuilder {
    /// Appends an item to `secret_list`.
    ///
    /// To override the contents of this collection use [`set_secret_list`](Self::set_secret_list).
    ///
    /// <p>A list of the secrets in the account.</p>
    pub fn secret_list(mut self, input: crate::types::SecretListEntry) -> Self {
        let mut v = self.secret_list.unwrap_or_default();
        v.push(input);
        self.secret_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of the secrets in the account.</p>
    pub fn set_secret_list(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SecretListEntry>>) -> Self {
        self.secret_list = input;
        self
    }
    /// <p>A list of the secrets in the account.</p>
    pub fn get_secret_list(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SecretListEntry>> {
        &self.secret_list
    }
    /// <p>Secrets Manager includes this value if there's more output available than what is included in the current response. This can occur even when the response includes no values at all, such as when you ask for a filtered view of a long list. To get the next results, call <code>ListSecrets</code> again with this value.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Secrets Manager includes this value if there's more output available than what is included in the current response. This can occur even when the response includes no values at all, such as when you ask for a filtered view of a long list. To get the next results, call <code>ListSecrets</code> again with this value.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>Secrets Manager includes this value if there's more output available than what is included in the current response. This can occur even when the response includes no values at all, such as when you ask for a filtered view of a long list. To get the next results, call <code>ListSecrets</code> again with this value.</p>
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
    /// Consumes the builder and constructs a [`ListSecretsOutput`](crate::operation::list_secrets::ListSecretsOutput).
    pub fn build(self) -> crate::operation::list_secrets::ListSecretsOutput {
        crate::operation::list_secrets::ListSecretsOutput {
            secret_list: self.secret_list,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
