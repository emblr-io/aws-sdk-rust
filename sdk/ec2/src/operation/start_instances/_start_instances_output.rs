// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartInstancesOutput {
    /// <p>Information about the started instances.</p>
    pub starting_instances: ::std::option::Option<::std::vec::Vec<crate::types::InstanceStateChange>>,
    _request_id: Option<String>,
}
impl StartInstancesOutput {
    /// <p>Information about the started instances.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.starting_instances.is_none()`.
    pub fn starting_instances(&self) -> &[crate::types::InstanceStateChange] {
        self.starting_instances.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for StartInstancesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StartInstancesOutput {
    /// Creates a new builder-style object to manufacture [`StartInstancesOutput`](crate::operation::start_instances::StartInstancesOutput).
    pub fn builder() -> crate::operation::start_instances::builders::StartInstancesOutputBuilder {
        crate::operation::start_instances::builders::StartInstancesOutputBuilder::default()
    }
}

/// A builder for [`StartInstancesOutput`](crate::operation::start_instances::StartInstancesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartInstancesOutputBuilder {
    pub(crate) starting_instances: ::std::option::Option<::std::vec::Vec<crate::types::InstanceStateChange>>,
    _request_id: Option<String>,
}
impl StartInstancesOutputBuilder {
    /// Appends an item to `starting_instances`.
    ///
    /// To override the contents of this collection use [`set_starting_instances`](Self::set_starting_instances).
    ///
    /// <p>Information about the started instances.</p>
    pub fn starting_instances(mut self, input: crate::types::InstanceStateChange) -> Self {
        let mut v = self.starting_instances.unwrap_or_default();
        v.push(input);
        self.starting_instances = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about the started instances.</p>
    pub fn set_starting_instances(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::InstanceStateChange>>) -> Self {
        self.starting_instances = input;
        self
    }
    /// <p>Information about the started instances.</p>
    pub fn get_starting_instances(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::InstanceStateChange>> {
        &self.starting_instances
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StartInstancesOutput`](crate::operation::start_instances::StartInstancesOutput).
    pub fn build(self) -> crate::operation::start_instances::StartInstancesOutput {
        crate::operation::start_instances::StartInstancesOutput {
            starting_instances: self.starting_instances,
            _request_id: self._request_id,
        }
    }
}
