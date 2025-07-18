// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The result of a <code>UpdateAvailabilityOptions</code> request. Contains the status of the domain's availability options.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateAvailabilityOptionsOutput {
    /// <p>The newly-configured availability options. Indicates whether Multi-AZ is enabled for the domain.</p>
    pub availability_options: ::std::option::Option<crate::types::AvailabilityOptionsStatus>,
    _request_id: Option<String>,
}
impl UpdateAvailabilityOptionsOutput {
    /// <p>The newly-configured availability options. Indicates whether Multi-AZ is enabled for the domain.</p>
    pub fn availability_options(&self) -> ::std::option::Option<&crate::types::AvailabilityOptionsStatus> {
        self.availability_options.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateAvailabilityOptionsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateAvailabilityOptionsOutput {
    /// Creates a new builder-style object to manufacture [`UpdateAvailabilityOptionsOutput`](crate::operation::update_availability_options::UpdateAvailabilityOptionsOutput).
    pub fn builder() -> crate::operation::update_availability_options::builders::UpdateAvailabilityOptionsOutputBuilder {
        crate::operation::update_availability_options::builders::UpdateAvailabilityOptionsOutputBuilder::default()
    }
}

/// A builder for [`UpdateAvailabilityOptionsOutput`](crate::operation::update_availability_options::UpdateAvailabilityOptionsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateAvailabilityOptionsOutputBuilder {
    pub(crate) availability_options: ::std::option::Option<crate::types::AvailabilityOptionsStatus>,
    _request_id: Option<String>,
}
impl UpdateAvailabilityOptionsOutputBuilder {
    /// <p>The newly-configured availability options. Indicates whether Multi-AZ is enabled for the domain.</p>
    pub fn availability_options(mut self, input: crate::types::AvailabilityOptionsStatus) -> Self {
        self.availability_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>The newly-configured availability options. Indicates whether Multi-AZ is enabled for the domain.</p>
    pub fn set_availability_options(mut self, input: ::std::option::Option<crate::types::AvailabilityOptionsStatus>) -> Self {
        self.availability_options = input;
        self
    }
    /// <p>The newly-configured availability options. Indicates whether Multi-AZ is enabled for the domain.</p>
    pub fn get_availability_options(&self) -> &::std::option::Option<crate::types::AvailabilityOptionsStatus> {
        &self.availability_options
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateAvailabilityOptionsOutput`](crate::operation::update_availability_options::UpdateAvailabilityOptionsOutput).
    pub fn build(self) -> crate::operation::update_availability_options::UpdateAvailabilityOptionsOutput {
        crate::operation::update_availability_options::UpdateAvailabilityOptionsOutput {
            availability_options: self.availability_options,
            _request_id: self._request_id,
        }
    }
}
