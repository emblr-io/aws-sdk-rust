// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteEnvironmentHostOutput {
    /// <p>A summary of the environment that the host was deleted from.</p>
    pub environment_summary: ::std::option::Option<crate::types::EnvironmentSummary>,
    /// <p>A description of the deleted host.</p>
    pub host: ::std::option::Option<crate::types::Host>,
    _request_id: Option<String>,
}
impl DeleteEnvironmentHostOutput {
    /// <p>A summary of the environment that the host was deleted from.</p>
    pub fn environment_summary(&self) -> ::std::option::Option<&crate::types::EnvironmentSummary> {
        self.environment_summary.as_ref()
    }
    /// <p>A description of the deleted host.</p>
    pub fn host(&self) -> ::std::option::Option<&crate::types::Host> {
        self.host.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DeleteEnvironmentHostOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteEnvironmentHostOutput {
    /// Creates a new builder-style object to manufacture [`DeleteEnvironmentHostOutput`](crate::operation::delete_environment_host::DeleteEnvironmentHostOutput).
    pub fn builder() -> crate::operation::delete_environment_host::builders::DeleteEnvironmentHostOutputBuilder {
        crate::operation::delete_environment_host::builders::DeleteEnvironmentHostOutputBuilder::default()
    }
}

/// A builder for [`DeleteEnvironmentHostOutput`](crate::operation::delete_environment_host::DeleteEnvironmentHostOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteEnvironmentHostOutputBuilder {
    pub(crate) environment_summary: ::std::option::Option<crate::types::EnvironmentSummary>,
    pub(crate) host: ::std::option::Option<crate::types::Host>,
    _request_id: Option<String>,
}
impl DeleteEnvironmentHostOutputBuilder {
    /// <p>A summary of the environment that the host was deleted from.</p>
    pub fn environment_summary(mut self, input: crate::types::EnvironmentSummary) -> Self {
        self.environment_summary = ::std::option::Option::Some(input);
        self
    }
    /// <p>A summary of the environment that the host was deleted from.</p>
    pub fn set_environment_summary(mut self, input: ::std::option::Option<crate::types::EnvironmentSummary>) -> Self {
        self.environment_summary = input;
        self
    }
    /// <p>A summary of the environment that the host was deleted from.</p>
    pub fn get_environment_summary(&self) -> &::std::option::Option<crate::types::EnvironmentSummary> {
        &self.environment_summary
    }
    /// <p>A description of the deleted host.</p>
    pub fn host(mut self, input: crate::types::Host) -> Self {
        self.host = ::std::option::Option::Some(input);
        self
    }
    /// <p>A description of the deleted host.</p>
    pub fn set_host(mut self, input: ::std::option::Option<crate::types::Host>) -> Self {
        self.host = input;
        self
    }
    /// <p>A description of the deleted host.</p>
    pub fn get_host(&self) -> &::std::option::Option<crate::types::Host> {
        &self.host
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteEnvironmentHostOutput`](crate::operation::delete_environment_host::DeleteEnvironmentHostOutput).
    pub fn build(self) -> crate::operation::delete_environment_host::DeleteEnvironmentHostOutput {
        crate::operation::delete_environment_host::DeleteEnvironmentHostOutput {
            environment_summary: self.environment_summary,
            host: self.host,
            _request_id: self._request_id,
        }
    }
}
