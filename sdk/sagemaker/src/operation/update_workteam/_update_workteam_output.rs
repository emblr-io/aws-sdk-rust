// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateWorkteamOutput {
    /// <p>A <code>Workteam</code> object that describes the updated work team.</p>
    pub workteam: ::std::option::Option<crate::types::Workteam>,
    _request_id: Option<String>,
}
impl UpdateWorkteamOutput {
    /// <p>A <code>Workteam</code> object that describes the updated work team.</p>
    pub fn workteam(&self) -> ::std::option::Option<&crate::types::Workteam> {
        self.workteam.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateWorkteamOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateWorkteamOutput {
    /// Creates a new builder-style object to manufacture [`UpdateWorkteamOutput`](crate::operation::update_workteam::UpdateWorkteamOutput).
    pub fn builder() -> crate::operation::update_workteam::builders::UpdateWorkteamOutputBuilder {
        crate::operation::update_workteam::builders::UpdateWorkteamOutputBuilder::default()
    }
}

/// A builder for [`UpdateWorkteamOutput`](crate::operation::update_workteam::UpdateWorkteamOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateWorkteamOutputBuilder {
    pub(crate) workteam: ::std::option::Option<crate::types::Workteam>,
    _request_id: Option<String>,
}
impl UpdateWorkteamOutputBuilder {
    /// <p>A <code>Workteam</code> object that describes the updated work team.</p>
    /// This field is required.
    pub fn workteam(mut self, input: crate::types::Workteam) -> Self {
        self.workteam = ::std::option::Option::Some(input);
        self
    }
    /// <p>A <code>Workteam</code> object that describes the updated work team.</p>
    pub fn set_workteam(mut self, input: ::std::option::Option<crate::types::Workteam>) -> Self {
        self.workteam = input;
        self
    }
    /// <p>A <code>Workteam</code> object that describes the updated work team.</p>
    pub fn get_workteam(&self) -> &::std::option::Option<crate::types::Workteam> {
        &self.workteam
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateWorkteamOutput`](crate::operation::update_workteam::UpdateWorkteamOutput).
    pub fn build(self) -> crate::operation::update_workteam::UpdateWorkteamOutput {
        crate::operation::update_workteam::UpdateWorkteamOutput {
            workteam: self.workteam,
            _request_id: self._request_id,
        }
    }
}
