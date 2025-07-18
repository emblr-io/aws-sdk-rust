// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutAccountPreferencesOutput {
    /// <p>Describes the resource type and its ID preference for the user's Amazon Web Services account, in the current Amazon Web Services Region.</p>
    pub resource_id_preference: ::std::option::Option<crate::types::ResourceIdPreference>,
    _request_id: Option<String>,
}
impl PutAccountPreferencesOutput {
    /// <p>Describes the resource type and its ID preference for the user's Amazon Web Services account, in the current Amazon Web Services Region.</p>
    pub fn resource_id_preference(&self) -> ::std::option::Option<&crate::types::ResourceIdPreference> {
        self.resource_id_preference.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for PutAccountPreferencesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl PutAccountPreferencesOutput {
    /// Creates a new builder-style object to manufacture [`PutAccountPreferencesOutput`](crate::operation::put_account_preferences::PutAccountPreferencesOutput).
    pub fn builder() -> crate::operation::put_account_preferences::builders::PutAccountPreferencesOutputBuilder {
        crate::operation::put_account_preferences::builders::PutAccountPreferencesOutputBuilder::default()
    }
}

/// A builder for [`PutAccountPreferencesOutput`](crate::operation::put_account_preferences::PutAccountPreferencesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutAccountPreferencesOutputBuilder {
    pub(crate) resource_id_preference: ::std::option::Option<crate::types::ResourceIdPreference>,
    _request_id: Option<String>,
}
impl PutAccountPreferencesOutputBuilder {
    /// <p>Describes the resource type and its ID preference for the user's Amazon Web Services account, in the current Amazon Web Services Region.</p>
    pub fn resource_id_preference(mut self, input: crate::types::ResourceIdPreference) -> Self {
        self.resource_id_preference = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes the resource type and its ID preference for the user's Amazon Web Services account, in the current Amazon Web Services Region.</p>
    pub fn set_resource_id_preference(mut self, input: ::std::option::Option<crate::types::ResourceIdPreference>) -> Self {
        self.resource_id_preference = input;
        self
    }
    /// <p>Describes the resource type and its ID preference for the user's Amazon Web Services account, in the current Amazon Web Services Region.</p>
    pub fn get_resource_id_preference(&self) -> &::std::option::Option<crate::types::ResourceIdPreference> {
        &self.resource_id_preference
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`PutAccountPreferencesOutput`](crate::operation::put_account_preferences::PutAccountPreferencesOutput).
    pub fn build(self) -> crate::operation::put_account_preferences::PutAccountPreferencesOutput {
        crate::operation::put_account_preferences::PutAccountPreferencesOutput {
            resource_id_preference: self.resource_id_preference,
            _request_id: self._request_id,
        }
    }
}
