// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DiscoverInstancesOutput {
    /// <p>A complex type that contains one <code>HttpInstanceSummary</code> for each registered instance.</p>
    pub instances: ::std::option::Option<::std::vec::Vec<crate::types::HttpInstanceSummary>>,
    /// <p>The increasing revision associated to the response Instances list. If a new instance is registered or deregistered, the <code>InstancesRevision</code> updates. The health status updates don't update <code>InstancesRevision</code>.</p>
    pub instances_revision: ::std::option::Option<i64>,
    _request_id: Option<String>,
}
impl DiscoverInstancesOutput {
    /// <p>A complex type that contains one <code>HttpInstanceSummary</code> for each registered instance.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.instances.is_none()`.
    pub fn instances(&self) -> &[crate::types::HttpInstanceSummary] {
        self.instances.as_deref().unwrap_or_default()
    }
    /// <p>The increasing revision associated to the response Instances list. If a new instance is registered or deregistered, the <code>InstancesRevision</code> updates. The health status updates don't update <code>InstancesRevision</code>.</p>
    pub fn instances_revision(&self) -> ::std::option::Option<i64> {
        self.instances_revision
    }
}
impl ::aws_types::request_id::RequestId for DiscoverInstancesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DiscoverInstancesOutput {
    /// Creates a new builder-style object to manufacture [`DiscoverInstancesOutput`](crate::operation::discover_instances::DiscoverInstancesOutput).
    pub fn builder() -> crate::operation::discover_instances::builders::DiscoverInstancesOutputBuilder {
        crate::operation::discover_instances::builders::DiscoverInstancesOutputBuilder::default()
    }
}

/// A builder for [`DiscoverInstancesOutput`](crate::operation::discover_instances::DiscoverInstancesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DiscoverInstancesOutputBuilder {
    pub(crate) instances: ::std::option::Option<::std::vec::Vec<crate::types::HttpInstanceSummary>>,
    pub(crate) instances_revision: ::std::option::Option<i64>,
    _request_id: Option<String>,
}
impl DiscoverInstancesOutputBuilder {
    /// Appends an item to `instances`.
    ///
    /// To override the contents of this collection use [`set_instances`](Self::set_instances).
    ///
    /// <p>A complex type that contains one <code>HttpInstanceSummary</code> for each registered instance.</p>
    pub fn instances(mut self, input: crate::types::HttpInstanceSummary) -> Self {
        let mut v = self.instances.unwrap_or_default();
        v.push(input);
        self.instances = ::std::option::Option::Some(v);
        self
    }
    /// <p>A complex type that contains one <code>HttpInstanceSummary</code> for each registered instance.</p>
    pub fn set_instances(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::HttpInstanceSummary>>) -> Self {
        self.instances = input;
        self
    }
    /// <p>A complex type that contains one <code>HttpInstanceSummary</code> for each registered instance.</p>
    pub fn get_instances(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::HttpInstanceSummary>> {
        &self.instances
    }
    /// <p>The increasing revision associated to the response Instances list. If a new instance is registered or deregistered, the <code>InstancesRevision</code> updates. The health status updates don't update <code>InstancesRevision</code>.</p>
    pub fn instances_revision(mut self, input: i64) -> Self {
        self.instances_revision = ::std::option::Option::Some(input);
        self
    }
    /// <p>The increasing revision associated to the response Instances list. If a new instance is registered or deregistered, the <code>InstancesRevision</code> updates. The health status updates don't update <code>InstancesRevision</code>.</p>
    pub fn set_instances_revision(mut self, input: ::std::option::Option<i64>) -> Self {
        self.instances_revision = input;
        self
    }
    /// <p>The increasing revision associated to the response Instances list. If a new instance is registered or deregistered, the <code>InstancesRevision</code> updates. The health status updates don't update <code>InstancesRevision</code>.</p>
    pub fn get_instances_revision(&self) -> &::std::option::Option<i64> {
        &self.instances_revision
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DiscoverInstancesOutput`](crate::operation::discover_instances::DiscoverInstancesOutput).
    pub fn build(self) -> crate::operation::discover_instances::DiscoverInstancesOutput {
        crate::operation::discover_instances::DiscoverInstancesOutput {
            instances: self.instances,
            instances_revision: self.instances_revision,
            _request_id: self._request_id,
        }
    }
}
