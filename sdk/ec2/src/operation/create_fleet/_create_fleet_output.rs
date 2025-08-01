// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateFleetOutput {
    /// <p>The ID of the EC2 Fleet.</p>
    pub fleet_id: ::std::option::Option<::std::string::String>,
    /// <p>Information about the instances that could not be launched by the fleet. Supported only for fleets of type <code>instant</code>.</p>
    pub errors: ::std::option::Option<::std::vec::Vec<crate::types::CreateFleetError>>,
    /// <p>Information about the instances that were launched by the fleet. Supported only for fleets of type <code>instant</code>.</p>
    pub instances: ::std::option::Option<::std::vec::Vec<crate::types::CreateFleetInstance>>,
    _request_id: Option<String>,
}
impl CreateFleetOutput {
    /// <p>The ID of the EC2 Fleet.</p>
    pub fn fleet_id(&self) -> ::std::option::Option<&str> {
        self.fleet_id.as_deref()
    }
    /// <p>Information about the instances that could not be launched by the fleet. Supported only for fleets of type <code>instant</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.errors.is_none()`.
    pub fn errors(&self) -> &[crate::types::CreateFleetError] {
        self.errors.as_deref().unwrap_or_default()
    }
    /// <p>Information about the instances that were launched by the fleet. Supported only for fleets of type <code>instant</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.instances.is_none()`.
    pub fn instances(&self) -> &[crate::types::CreateFleetInstance] {
        self.instances.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for CreateFleetOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateFleetOutput {
    /// Creates a new builder-style object to manufacture [`CreateFleetOutput`](crate::operation::create_fleet::CreateFleetOutput).
    pub fn builder() -> crate::operation::create_fleet::builders::CreateFleetOutputBuilder {
        crate::operation::create_fleet::builders::CreateFleetOutputBuilder::default()
    }
}

/// A builder for [`CreateFleetOutput`](crate::operation::create_fleet::CreateFleetOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateFleetOutputBuilder {
    pub(crate) fleet_id: ::std::option::Option<::std::string::String>,
    pub(crate) errors: ::std::option::Option<::std::vec::Vec<crate::types::CreateFleetError>>,
    pub(crate) instances: ::std::option::Option<::std::vec::Vec<crate::types::CreateFleetInstance>>,
    _request_id: Option<String>,
}
impl CreateFleetOutputBuilder {
    /// <p>The ID of the EC2 Fleet.</p>
    pub fn fleet_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.fleet_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the EC2 Fleet.</p>
    pub fn set_fleet_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.fleet_id = input;
        self
    }
    /// <p>The ID of the EC2 Fleet.</p>
    pub fn get_fleet_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.fleet_id
    }
    /// Appends an item to `errors`.
    ///
    /// To override the contents of this collection use [`set_errors`](Self::set_errors).
    ///
    /// <p>Information about the instances that could not be launched by the fleet. Supported only for fleets of type <code>instant</code>.</p>
    pub fn errors(mut self, input: crate::types::CreateFleetError) -> Self {
        let mut v = self.errors.unwrap_or_default();
        v.push(input);
        self.errors = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about the instances that could not be launched by the fleet. Supported only for fleets of type <code>instant</code>.</p>
    pub fn set_errors(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CreateFleetError>>) -> Self {
        self.errors = input;
        self
    }
    /// <p>Information about the instances that could not be launched by the fleet. Supported only for fleets of type <code>instant</code>.</p>
    pub fn get_errors(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CreateFleetError>> {
        &self.errors
    }
    /// Appends an item to `instances`.
    ///
    /// To override the contents of this collection use [`set_instances`](Self::set_instances).
    ///
    /// <p>Information about the instances that were launched by the fleet. Supported only for fleets of type <code>instant</code>.</p>
    pub fn instances(mut self, input: crate::types::CreateFleetInstance) -> Self {
        let mut v = self.instances.unwrap_or_default();
        v.push(input);
        self.instances = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about the instances that were launched by the fleet. Supported only for fleets of type <code>instant</code>.</p>
    pub fn set_instances(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CreateFleetInstance>>) -> Self {
        self.instances = input;
        self
    }
    /// <p>Information about the instances that were launched by the fleet. Supported only for fleets of type <code>instant</code>.</p>
    pub fn get_instances(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CreateFleetInstance>> {
        &self.instances
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateFleetOutput`](crate::operation::create_fleet::CreateFleetOutput).
    pub fn build(self) -> crate::operation::create_fleet::CreateFleetOutput {
        crate::operation::create_fleet::CreateFleetOutput {
            fleet_id: self.fleet_id,
            errors: self.errors,
            instances: self.instances,
            _request_id: self._request_id,
        }
    }
}
