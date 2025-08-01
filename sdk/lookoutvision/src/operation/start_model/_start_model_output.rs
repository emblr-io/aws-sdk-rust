// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartModelOutput {
    /// <p>The current running status of the model.</p>
    pub status: ::std::option::Option<crate::types::ModelHostingStatus>,
    _request_id: Option<String>,
}
impl StartModelOutput {
    /// <p>The current running status of the model.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::ModelHostingStatus> {
        self.status.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for StartModelOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StartModelOutput {
    /// Creates a new builder-style object to manufacture [`StartModelOutput`](crate::operation::start_model::StartModelOutput).
    pub fn builder() -> crate::operation::start_model::builders::StartModelOutputBuilder {
        crate::operation::start_model::builders::StartModelOutputBuilder::default()
    }
}

/// A builder for [`StartModelOutput`](crate::operation::start_model::StartModelOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartModelOutputBuilder {
    pub(crate) status: ::std::option::Option<crate::types::ModelHostingStatus>,
    _request_id: Option<String>,
}
impl StartModelOutputBuilder {
    /// <p>The current running status of the model.</p>
    pub fn status(mut self, input: crate::types::ModelHostingStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current running status of the model.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::ModelHostingStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The current running status of the model.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::ModelHostingStatus> {
        &self.status
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StartModelOutput`](crate::operation::start_model::StartModelOutput).
    pub fn build(self) -> crate::operation::start_model::StartModelOutput {
        crate::operation::start_model::StartModelOutput {
            status: self.status,
            _request_id: self._request_id,
        }
    }
}
