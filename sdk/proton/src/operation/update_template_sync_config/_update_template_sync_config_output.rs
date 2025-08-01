// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateTemplateSyncConfigOutput {
    /// <p>The template sync configuration detail data that's returned by Proton.</p>
    pub template_sync_config: ::std::option::Option<crate::types::TemplateSyncConfig>,
    _request_id: Option<String>,
}
impl UpdateTemplateSyncConfigOutput {
    /// <p>The template sync configuration detail data that's returned by Proton.</p>
    pub fn template_sync_config(&self) -> ::std::option::Option<&crate::types::TemplateSyncConfig> {
        self.template_sync_config.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateTemplateSyncConfigOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateTemplateSyncConfigOutput {
    /// Creates a new builder-style object to manufacture [`UpdateTemplateSyncConfigOutput`](crate::operation::update_template_sync_config::UpdateTemplateSyncConfigOutput).
    pub fn builder() -> crate::operation::update_template_sync_config::builders::UpdateTemplateSyncConfigOutputBuilder {
        crate::operation::update_template_sync_config::builders::UpdateTemplateSyncConfigOutputBuilder::default()
    }
}

/// A builder for [`UpdateTemplateSyncConfigOutput`](crate::operation::update_template_sync_config::UpdateTemplateSyncConfigOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateTemplateSyncConfigOutputBuilder {
    pub(crate) template_sync_config: ::std::option::Option<crate::types::TemplateSyncConfig>,
    _request_id: Option<String>,
}
impl UpdateTemplateSyncConfigOutputBuilder {
    /// <p>The template sync configuration detail data that's returned by Proton.</p>
    pub fn template_sync_config(mut self, input: crate::types::TemplateSyncConfig) -> Self {
        self.template_sync_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The template sync configuration detail data that's returned by Proton.</p>
    pub fn set_template_sync_config(mut self, input: ::std::option::Option<crate::types::TemplateSyncConfig>) -> Self {
        self.template_sync_config = input;
        self
    }
    /// <p>The template sync configuration detail data that's returned by Proton.</p>
    pub fn get_template_sync_config(&self) -> &::std::option::Option<crate::types::TemplateSyncConfig> {
        &self.template_sync_config
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateTemplateSyncConfigOutput`](crate::operation::update_template_sync_config::UpdateTemplateSyncConfigOutput).
    pub fn build(self) -> crate::operation::update_template_sync_config::UpdateTemplateSyncConfigOutput {
        crate::operation::update_template_sync_config::UpdateTemplateSyncConfigOutput {
            template_sync_config: self.template_sync_config,
            _request_id: self._request_id,
        }
    }
}
