// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Output from an AddInstanceGroups call.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AddInstanceGroupsOutput {
    /// <p>The job flow ID in which the instance groups are added.</p>
    pub job_flow_id: ::std::option::Option<::std::string::String>,
    /// <p>Instance group IDs of the newly created instance groups.</p>
    pub instance_group_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The Amazon Resource Name of the cluster.</p>
    pub cluster_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl AddInstanceGroupsOutput {
    /// <p>The job flow ID in which the instance groups are added.</p>
    pub fn job_flow_id(&self) -> ::std::option::Option<&str> {
        self.job_flow_id.as_deref()
    }
    /// <p>Instance group IDs of the newly created instance groups.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.instance_group_ids.is_none()`.
    pub fn instance_group_ids(&self) -> &[::std::string::String] {
        self.instance_group_ids.as_deref().unwrap_or_default()
    }
    /// <p>The Amazon Resource Name of the cluster.</p>
    pub fn cluster_arn(&self) -> ::std::option::Option<&str> {
        self.cluster_arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for AddInstanceGroupsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl AddInstanceGroupsOutput {
    /// Creates a new builder-style object to manufacture [`AddInstanceGroupsOutput`](crate::operation::add_instance_groups::AddInstanceGroupsOutput).
    pub fn builder() -> crate::operation::add_instance_groups::builders::AddInstanceGroupsOutputBuilder {
        crate::operation::add_instance_groups::builders::AddInstanceGroupsOutputBuilder::default()
    }
}

/// A builder for [`AddInstanceGroupsOutput`](crate::operation::add_instance_groups::AddInstanceGroupsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AddInstanceGroupsOutputBuilder {
    pub(crate) job_flow_id: ::std::option::Option<::std::string::String>,
    pub(crate) instance_group_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) cluster_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl AddInstanceGroupsOutputBuilder {
    /// <p>The job flow ID in which the instance groups are added.</p>
    pub fn job_flow_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_flow_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The job flow ID in which the instance groups are added.</p>
    pub fn set_job_flow_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_flow_id = input;
        self
    }
    /// <p>The job flow ID in which the instance groups are added.</p>
    pub fn get_job_flow_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_flow_id
    }
    /// Appends an item to `instance_group_ids`.
    ///
    /// To override the contents of this collection use [`set_instance_group_ids`](Self::set_instance_group_ids).
    ///
    /// <p>Instance group IDs of the newly created instance groups.</p>
    pub fn instance_group_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.instance_group_ids.unwrap_or_default();
        v.push(input.into());
        self.instance_group_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>Instance group IDs of the newly created instance groups.</p>
    pub fn set_instance_group_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.instance_group_ids = input;
        self
    }
    /// <p>Instance group IDs of the newly created instance groups.</p>
    pub fn get_instance_group_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.instance_group_ids
    }
    /// <p>The Amazon Resource Name of the cluster.</p>
    pub fn cluster_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cluster_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name of the cluster.</p>
    pub fn set_cluster_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cluster_arn = input;
        self
    }
    /// <p>The Amazon Resource Name of the cluster.</p>
    pub fn get_cluster_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.cluster_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`AddInstanceGroupsOutput`](crate::operation::add_instance_groups::AddInstanceGroupsOutput).
    pub fn build(self) -> crate::operation::add_instance_groups::AddInstanceGroupsOutput {
        crate::operation::add_instance_groups::AddInstanceGroupsOutput {
            job_flow_id: self.job_flow_id,
            instance_group_ids: self.instance_group_ids,
            cluster_arn: self.cluster_arn,
            _request_id: self._request_id,
        }
    }
}
