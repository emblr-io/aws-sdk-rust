// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateRepositoryDescriptionOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for UpdateRepositoryDescriptionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateRepositoryDescriptionOutput {
    /// Creates a new builder-style object to manufacture [`UpdateRepositoryDescriptionOutput`](crate::operation::update_repository_description::UpdateRepositoryDescriptionOutput).
    pub fn builder() -> crate::operation::update_repository_description::builders::UpdateRepositoryDescriptionOutputBuilder {
        crate::operation::update_repository_description::builders::UpdateRepositoryDescriptionOutputBuilder::default()
    }
}

/// A builder for [`UpdateRepositoryDescriptionOutput`](crate::operation::update_repository_description::UpdateRepositoryDescriptionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateRepositoryDescriptionOutputBuilder {
    _request_id: Option<String>,
}
impl UpdateRepositoryDescriptionOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateRepositoryDescriptionOutput`](crate::operation::update_repository_description::UpdateRepositoryDescriptionOutput).
    pub fn build(self) -> crate::operation::update_repository_description::UpdateRepositoryDescriptionOutput {
        crate::operation::update_repository_description::UpdateRepositoryDescriptionOutput {
            _request_id: self._request_id,
        }
    }
}
