// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateEnvironmentOutput {
    /// <p>Describes an environment.</p>
    pub environment: ::std::option::Option<crate::types::EnvironmentSummary>,
    _request_id: Option<String>,
}
impl UpdateEnvironmentOutput {
    /// <p>Describes an environment.</p>
    pub fn environment(&self) -> ::std::option::Option<&crate::types::EnvironmentSummary> {
        self.environment.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateEnvironmentOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateEnvironmentOutput {
    /// Creates a new builder-style object to manufacture [`UpdateEnvironmentOutput`](crate::operation::update_environment::UpdateEnvironmentOutput).
    pub fn builder() -> crate::operation::update_environment::builders::UpdateEnvironmentOutputBuilder {
        crate::operation::update_environment::builders::UpdateEnvironmentOutputBuilder::default()
    }
}

/// A builder for [`UpdateEnvironmentOutput`](crate::operation::update_environment::UpdateEnvironmentOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateEnvironmentOutputBuilder {
    pub(crate) environment: ::std::option::Option<crate::types::EnvironmentSummary>,
    _request_id: Option<String>,
}
impl UpdateEnvironmentOutputBuilder {
    /// <p>Describes an environment.</p>
    pub fn environment(mut self, input: crate::types::EnvironmentSummary) -> Self {
        self.environment = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes an environment.</p>
    pub fn set_environment(mut self, input: ::std::option::Option<crate::types::EnvironmentSummary>) -> Self {
        self.environment = input;
        self
    }
    /// <p>Describes an environment.</p>
    pub fn get_environment(&self) -> &::std::option::Option<crate::types::EnvironmentSummary> {
        &self.environment
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateEnvironmentOutput`](crate::operation::update_environment::UpdateEnvironmentOutput).
    pub fn build(self) -> crate::operation::update_environment::UpdateEnvironmentOutput {
        crate::operation::update_environment::UpdateEnvironmentOutput {
            environment: self.environment,
            _request_id: self._request_id,
        }
    }
}
