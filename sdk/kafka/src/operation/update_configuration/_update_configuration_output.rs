// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateConfigurationOutput {
    /// <p>The Amazon Resource Name (ARN) of the configuration.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>Latest revision of the configuration.</p>
    pub latest_revision: ::std::option::Option<crate::types::ConfigurationRevision>,
    _request_id: Option<String>,
}
impl UpdateConfigurationOutput {
    /// <p>The Amazon Resource Name (ARN) of the configuration.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>Latest revision of the configuration.</p>
    pub fn latest_revision(&self) -> ::std::option::Option<&crate::types::ConfigurationRevision> {
        self.latest_revision.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`UpdateConfigurationOutput`](crate::operation::update_configuration::UpdateConfigurationOutput).
    pub fn builder() -> crate::operation::update_configuration::builders::UpdateConfigurationOutputBuilder {
        crate::operation::update_configuration::builders::UpdateConfigurationOutputBuilder::default()
    }
}

/// A builder for [`UpdateConfigurationOutput`](crate::operation::update_configuration::UpdateConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateConfigurationOutputBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) latest_revision: ::std::option::Option<crate::types::ConfigurationRevision>,
    _request_id: Option<String>,
}
impl UpdateConfigurationOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the configuration.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the configuration.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the configuration.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>Latest revision of the configuration.</p>
    pub fn latest_revision(mut self, input: crate::types::ConfigurationRevision) -> Self {
        self.latest_revision = ::std::option::Option::Some(input);
        self
    }
    /// <p>Latest revision of the configuration.</p>
    pub fn set_latest_revision(mut self, input: ::std::option::Option<crate::types::ConfigurationRevision>) -> Self {
        self.latest_revision = input;
        self
    }
    /// <p>Latest revision of the configuration.</p>
    pub fn get_latest_revision(&self) -> &::std::option::Option<crate::types::ConfigurationRevision> {
        &self.latest_revision
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateConfigurationOutput`](crate::operation::update_configuration::UpdateConfigurationOutput).
    pub fn build(self) -> crate::operation::update_configuration::UpdateConfigurationOutput {
        crate::operation::update_configuration::UpdateConfigurationOutput {
            arn: self.arn,
            latest_revision: self.latest_revision,
            _request_id: self._request_id,
        }
    }
}
