// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutAccountSettingOutput {
    /// <p>The current account setting for a resource.</p>
    pub setting: ::std::option::Option<crate::types::Setting>,
    _request_id: Option<String>,
}
impl PutAccountSettingOutput {
    /// <p>The current account setting for a resource.</p>
    pub fn setting(&self) -> ::std::option::Option<&crate::types::Setting> {
        self.setting.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for PutAccountSettingOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl PutAccountSettingOutput {
    /// Creates a new builder-style object to manufacture [`PutAccountSettingOutput`](crate::operation::put_account_setting::PutAccountSettingOutput).
    pub fn builder() -> crate::operation::put_account_setting::builders::PutAccountSettingOutputBuilder {
        crate::operation::put_account_setting::builders::PutAccountSettingOutputBuilder::default()
    }
}

/// A builder for [`PutAccountSettingOutput`](crate::operation::put_account_setting::PutAccountSettingOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutAccountSettingOutputBuilder {
    pub(crate) setting: ::std::option::Option<crate::types::Setting>,
    _request_id: Option<String>,
}
impl PutAccountSettingOutputBuilder {
    /// <p>The current account setting for a resource.</p>
    pub fn setting(mut self, input: crate::types::Setting) -> Self {
        self.setting = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current account setting for a resource.</p>
    pub fn set_setting(mut self, input: ::std::option::Option<crate::types::Setting>) -> Self {
        self.setting = input;
        self
    }
    /// <p>The current account setting for a resource.</p>
    pub fn get_setting(&self) -> &::std::option::Option<crate::types::Setting> {
        &self.setting
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`PutAccountSettingOutput`](crate::operation::put_account_setting::PutAccountSettingOutput).
    pub fn build(self) -> crate::operation::put_account_setting::PutAccountSettingOutput {
        crate::operation::put_account_setting::PutAccountSettingOutput {
            setting: self.setting,
            _request_id: self._request_id,
        }
    }
}
