// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateAccountPreferencesOutput {
    /// <p>Preferences related to AWS Chatbot usage in the calling AWS account.</p>
    pub account_preferences: ::std::option::Option<crate::types::AccountPreferences>,
    _request_id: Option<String>,
}
impl UpdateAccountPreferencesOutput {
    /// <p>Preferences related to AWS Chatbot usage in the calling AWS account.</p>
    pub fn account_preferences(&self) -> ::std::option::Option<&crate::types::AccountPreferences> {
        self.account_preferences.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateAccountPreferencesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateAccountPreferencesOutput {
    /// Creates a new builder-style object to manufacture [`UpdateAccountPreferencesOutput`](crate::operation::update_account_preferences::UpdateAccountPreferencesOutput).
    pub fn builder() -> crate::operation::update_account_preferences::builders::UpdateAccountPreferencesOutputBuilder {
        crate::operation::update_account_preferences::builders::UpdateAccountPreferencesOutputBuilder::default()
    }
}

/// A builder for [`UpdateAccountPreferencesOutput`](crate::operation::update_account_preferences::UpdateAccountPreferencesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateAccountPreferencesOutputBuilder {
    pub(crate) account_preferences: ::std::option::Option<crate::types::AccountPreferences>,
    _request_id: Option<String>,
}
impl UpdateAccountPreferencesOutputBuilder {
    /// <p>Preferences related to AWS Chatbot usage in the calling AWS account.</p>
    pub fn account_preferences(mut self, input: crate::types::AccountPreferences) -> Self {
        self.account_preferences = ::std::option::Option::Some(input);
        self
    }
    /// <p>Preferences related to AWS Chatbot usage in the calling AWS account.</p>
    pub fn set_account_preferences(mut self, input: ::std::option::Option<crate::types::AccountPreferences>) -> Self {
        self.account_preferences = input;
        self
    }
    /// <p>Preferences related to AWS Chatbot usage in the calling AWS account.</p>
    pub fn get_account_preferences(&self) -> &::std::option::Option<crate::types::AccountPreferences> {
        &self.account_preferences
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateAccountPreferencesOutput`](crate::operation::update_account_preferences::UpdateAccountPreferencesOutput).
    pub fn build(self) -> crate::operation::update_account_preferences::UpdateAccountPreferencesOutput {
        crate::operation::update_account_preferences::UpdateAccountPreferencesOutput {
            account_preferences: self.account_preferences,
            _request_id: self._request_id,
        }
    }
}
