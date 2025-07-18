// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateInstanceProfileOutput {
    /// <p>An object that contains information about your instance profile.</p>
    pub instance_profile: ::std::option::Option<crate::types::InstanceProfile>,
    _request_id: Option<String>,
}
impl UpdateInstanceProfileOutput {
    /// <p>An object that contains information about your instance profile.</p>
    pub fn instance_profile(&self) -> ::std::option::Option<&crate::types::InstanceProfile> {
        self.instance_profile.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateInstanceProfileOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateInstanceProfileOutput {
    /// Creates a new builder-style object to manufacture [`UpdateInstanceProfileOutput`](crate::operation::update_instance_profile::UpdateInstanceProfileOutput).
    pub fn builder() -> crate::operation::update_instance_profile::builders::UpdateInstanceProfileOutputBuilder {
        crate::operation::update_instance_profile::builders::UpdateInstanceProfileOutputBuilder::default()
    }
}

/// A builder for [`UpdateInstanceProfileOutput`](crate::operation::update_instance_profile::UpdateInstanceProfileOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateInstanceProfileOutputBuilder {
    pub(crate) instance_profile: ::std::option::Option<crate::types::InstanceProfile>,
    _request_id: Option<String>,
}
impl UpdateInstanceProfileOutputBuilder {
    /// <p>An object that contains information about your instance profile.</p>
    pub fn instance_profile(mut self, input: crate::types::InstanceProfile) -> Self {
        self.instance_profile = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that contains information about your instance profile.</p>
    pub fn set_instance_profile(mut self, input: ::std::option::Option<crate::types::InstanceProfile>) -> Self {
        self.instance_profile = input;
        self
    }
    /// <p>An object that contains information about your instance profile.</p>
    pub fn get_instance_profile(&self) -> &::std::option::Option<crate::types::InstanceProfile> {
        &self.instance_profile
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateInstanceProfileOutput`](crate::operation::update_instance_profile::UpdateInstanceProfileOutput).
    pub fn build(self) -> crate::operation::update_instance_profile::UpdateInstanceProfileOutput {
        crate::operation::update_instance_profile::UpdateInstanceProfileOutput {
            instance_profile: self.instance_profile,
            _request_id: self._request_id,
        }
    }
}
