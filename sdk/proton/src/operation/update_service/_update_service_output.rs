// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateServiceOutput {
    /// <p>The service detail data that's returned by Proton.</p>
    pub service: ::std::option::Option<crate::types::Service>,
    _request_id: Option<String>,
}
impl UpdateServiceOutput {
    /// <p>The service detail data that's returned by Proton.</p>
    pub fn service(&self) -> ::std::option::Option<&crate::types::Service> {
        self.service.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateServiceOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateServiceOutput {
    /// Creates a new builder-style object to manufacture [`UpdateServiceOutput`](crate::operation::update_service::UpdateServiceOutput).
    pub fn builder() -> crate::operation::update_service::builders::UpdateServiceOutputBuilder {
        crate::operation::update_service::builders::UpdateServiceOutputBuilder::default()
    }
}

/// A builder for [`UpdateServiceOutput`](crate::operation::update_service::UpdateServiceOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateServiceOutputBuilder {
    pub(crate) service: ::std::option::Option<crate::types::Service>,
    _request_id: Option<String>,
}
impl UpdateServiceOutputBuilder {
    /// <p>The service detail data that's returned by Proton.</p>
    /// This field is required.
    pub fn service(mut self, input: crate::types::Service) -> Self {
        self.service = ::std::option::Option::Some(input);
        self
    }
    /// <p>The service detail data that's returned by Proton.</p>
    pub fn set_service(mut self, input: ::std::option::Option<crate::types::Service>) -> Self {
        self.service = input;
        self
    }
    /// <p>The service detail data that's returned by Proton.</p>
    pub fn get_service(&self) -> &::std::option::Option<crate::types::Service> {
        &self.service
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateServiceOutput`](crate::operation::update_service::UpdateServiceOutput).
    pub fn build(self) -> crate::operation::update_service::UpdateServiceOutput {
        crate::operation::update_service::UpdateServiceOutput {
            service: self.service,
            _request_id: self._request_id,
        }
    }
}
