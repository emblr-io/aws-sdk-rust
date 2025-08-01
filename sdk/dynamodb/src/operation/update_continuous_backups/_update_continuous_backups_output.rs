// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateContinuousBackupsOutput {
    /// <p>Represents the continuous backups and point in time recovery settings on the table.</p>
    pub continuous_backups_description: ::std::option::Option<crate::types::ContinuousBackupsDescription>,
    _request_id: Option<String>,
}
impl UpdateContinuousBackupsOutput {
    /// <p>Represents the continuous backups and point in time recovery settings on the table.</p>
    pub fn continuous_backups_description(&self) -> ::std::option::Option<&crate::types::ContinuousBackupsDescription> {
        self.continuous_backups_description.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateContinuousBackupsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateContinuousBackupsOutput {
    /// Creates a new builder-style object to manufacture [`UpdateContinuousBackupsOutput`](crate::operation::update_continuous_backups::UpdateContinuousBackupsOutput).
    pub fn builder() -> crate::operation::update_continuous_backups::builders::UpdateContinuousBackupsOutputBuilder {
        crate::operation::update_continuous_backups::builders::UpdateContinuousBackupsOutputBuilder::default()
    }
}

/// A builder for [`UpdateContinuousBackupsOutput`](crate::operation::update_continuous_backups::UpdateContinuousBackupsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateContinuousBackupsOutputBuilder {
    pub(crate) continuous_backups_description: ::std::option::Option<crate::types::ContinuousBackupsDescription>,
    _request_id: Option<String>,
}
impl UpdateContinuousBackupsOutputBuilder {
    /// <p>Represents the continuous backups and point in time recovery settings on the table.</p>
    pub fn continuous_backups_description(mut self, input: crate::types::ContinuousBackupsDescription) -> Self {
        self.continuous_backups_description = ::std::option::Option::Some(input);
        self
    }
    /// <p>Represents the continuous backups and point in time recovery settings on the table.</p>
    pub fn set_continuous_backups_description(mut self, input: ::std::option::Option<crate::types::ContinuousBackupsDescription>) -> Self {
        self.continuous_backups_description = input;
        self
    }
    /// <p>Represents the continuous backups and point in time recovery settings on the table.</p>
    pub fn get_continuous_backups_description(&self) -> &::std::option::Option<crate::types::ContinuousBackupsDescription> {
        &self.continuous_backups_description
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateContinuousBackupsOutput`](crate::operation::update_continuous_backups::UpdateContinuousBackupsOutput).
    pub fn build(self) -> crate::operation::update_continuous_backups::UpdateContinuousBackupsOutput {
        crate::operation::update_continuous_backups::UpdateContinuousBackupsOutput {
            continuous_backups_description: self.continuous_backups_description,
            _request_id: self._request_id,
        }
    }
}
