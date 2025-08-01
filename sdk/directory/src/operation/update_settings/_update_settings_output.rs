// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateSettingsOutput {
    /// <p>The identifier of the directory.</p>
    pub directory_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl UpdateSettingsOutput {
    /// <p>The identifier of the directory.</p>
    pub fn directory_id(&self) -> ::std::option::Option<&str> {
        self.directory_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateSettingsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateSettingsOutput {
    /// Creates a new builder-style object to manufacture [`UpdateSettingsOutput`](crate::operation::update_settings::UpdateSettingsOutput).
    pub fn builder() -> crate::operation::update_settings::builders::UpdateSettingsOutputBuilder {
        crate::operation::update_settings::builders::UpdateSettingsOutputBuilder::default()
    }
}

/// A builder for [`UpdateSettingsOutput`](crate::operation::update_settings::UpdateSettingsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateSettingsOutputBuilder {
    pub(crate) directory_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl UpdateSettingsOutputBuilder {
    /// <p>The identifier of the directory.</p>
    pub fn directory_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.directory_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the directory.</p>
    pub fn set_directory_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.directory_id = input;
        self
    }
    /// <p>The identifier of the directory.</p>
    pub fn get_directory_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.directory_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateSettingsOutput`](crate::operation::update_settings::UpdateSettingsOutput).
    pub fn build(self) -> crate::operation::update_settings::UpdateSettingsOutput {
        crate::operation::update_settings::UpdateSettingsOutput {
            directory_id: self.directory_id,
            _request_id: self._request_id,
        }
    }
}
