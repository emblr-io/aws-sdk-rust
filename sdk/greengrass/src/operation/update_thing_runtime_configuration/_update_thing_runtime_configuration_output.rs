// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateThingRuntimeConfigurationOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for UpdateThingRuntimeConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateThingRuntimeConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`UpdateThingRuntimeConfigurationOutput`](crate::operation::update_thing_runtime_configuration::UpdateThingRuntimeConfigurationOutput).
    pub fn builder() -> crate::operation::update_thing_runtime_configuration::builders::UpdateThingRuntimeConfigurationOutputBuilder {
        crate::operation::update_thing_runtime_configuration::builders::UpdateThingRuntimeConfigurationOutputBuilder::default()
    }
}

/// A builder for [`UpdateThingRuntimeConfigurationOutput`](crate::operation::update_thing_runtime_configuration::UpdateThingRuntimeConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateThingRuntimeConfigurationOutputBuilder {
    _request_id: Option<String>,
}
impl UpdateThingRuntimeConfigurationOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateThingRuntimeConfigurationOutput`](crate::operation::update_thing_runtime_configuration::UpdateThingRuntimeConfigurationOutput).
    pub fn build(self) -> crate::operation::update_thing_runtime_configuration::UpdateThingRuntimeConfigurationOutput {
        crate::operation::update_thing_runtime_configuration::UpdateThingRuntimeConfigurationOutput {
            _request_id: self._request_id,
        }
    }
}
