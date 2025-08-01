// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>This input determines which instances to list.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListInstancesInput {
    /// <p>The identifier of the cluster for which to list the instances.</p>
    pub cluster_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the instance group for which to list the instances.</p>
    pub instance_group_id: ::std::option::Option<::std::string::String>,
    /// <p>The type of instance group for which to list the instances.</p>
    pub instance_group_types: ::std::option::Option<::std::vec::Vec<crate::types::InstanceGroupType>>,
    /// <p>The unique identifier of the instance fleet.</p>
    pub instance_fleet_id: ::std::option::Option<::std::string::String>,
    /// <p>The node type of the instance fleet. For example MASTER, CORE, or TASK.</p>
    pub instance_fleet_type: ::std::option::Option<crate::types::InstanceFleetType>,
    /// <p>A list of instance states that will filter the instances returned with this request.</p>
    pub instance_states: ::std::option::Option<::std::vec::Vec<crate::types::InstanceState>>,
    /// <p>The pagination token that indicates the next set of results to retrieve.</p>
    pub marker: ::std::option::Option<::std::string::String>,
}
impl ListInstancesInput {
    /// <p>The identifier of the cluster for which to list the instances.</p>
    pub fn cluster_id(&self) -> ::std::option::Option<&str> {
        self.cluster_id.as_deref()
    }
    /// <p>The identifier of the instance group for which to list the instances.</p>
    pub fn instance_group_id(&self) -> ::std::option::Option<&str> {
        self.instance_group_id.as_deref()
    }
    /// <p>The type of instance group for which to list the instances.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.instance_group_types.is_none()`.
    pub fn instance_group_types(&self) -> &[crate::types::InstanceGroupType] {
        self.instance_group_types.as_deref().unwrap_or_default()
    }
    /// <p>The unique identifier of the instance fleet.</p>
    pub fn instance_fleet_id(&self) -> ::std::option::Option<&str> {
        self.instance_fleet_id.as_deref()
    }
    /// <p>The node type of the instance fleet. For example MASTER, CORE, or TASK.</p>
    pub fn instance_fleet_type(&self) -> ::std::option::Option<&crate::types::InstanceFleetType> {
        self.instance_fleet_type.as_ref()
    }
    /// <p>A list of instance states that will filter the instances returned with this request.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.instance_states.is_none()`.
    pub fn instance_states(&self) -> &[crate::types::InstanceState] {
        self.instance_states.as_deref().unwrap_or_default()
    }
    /// <p>The pagination token that indicates the next set of results to retrieve.</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
}
impl ListInstancesInput {
    /// Creates a new builder-style object to manufacture [`ListInstancesInput`](crate::operation::list_instances::ListInstancesInput).
    pub fn builder() -> crate::operation::list_instances::builders::ListInstancesInputBuilder {
        crate::operation::list_instances::builders::ListInstancesInputBuilder::default()
    }
}

/// A builder for [`ListInstancesInput`](crate::operation::list_instances::ListInstancesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListInstancesInputBuilder {
    pub(crate) cluster_id: ::std::option::Option<::std::string::String>,
    pub(crate) instance_group_id: ::std::option::Option<::std::string::String>,
    pub(crate) instance_group_types: ::std::option::Option<::std::vec::Vec<crate::types::InstanceGroupType>>,
    pub(crate) instance_fleet_id: ::std::option::Option<::std::string::String>,
    pub(crate) instance_fleet_type: ::std::option::Option<crate::types::InstanceFleetType>,
    pub(crate) instance_states: ::std::option::Option<::std::vec::Vec<crate::types::InstanceState>>,
    pub(crate) marker: ::std::option::Option<::std::string::String>,
}
impl ListInstancesInputBuilder {
    /// <p>The identifier of the cluster for which to list the instances.</p>
    /// This field is required.
    pub fn cluster_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cluster_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the cluster for which to list the instances.</p>
    pub fn set_cluster_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cluster_id = input;
        self
    }
    /// <p>The identifier of the cluster for which to list the instances.</p>
    pub fn get_cluster_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.cluster_id
    }
    /// <p>The identifier of the instance group for which to list the instances.</p>
    pub fn instance_group_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_group_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the instance group for which to list the instances.</p>
    pub fn set_instance_group_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_group_id = input;
        self
    }
    /// <p>The identifier of the instance group for which to list the instances.</p>
    pub fn get_instance_group_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_group_id
    }
    /// Appends an item to `instance_group_types`.
    ///
    /// To override the contents of this collection use [`set_instance_group_types`](Self::set_instance_group_types).
    ///
    /// <p>The type of instance group for which to list the instances.</p>
    pub fn instance_group_types(mut self, input: crate::types::InstanceGroupType) -> Self {
        let mut v = self.instance_group_types.unwrap_or_default();
        v.push(input);
        self.instance_group_types = ::std::option::Option::Some(v);
        self
    }
    /// <p>The type of instance group for which to list the instances.</p>
    pub fn set_instance_group_types(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::InstanceGroupType>>) -> Self {
        self.instance_group_types = input;
        self
    }
    /// <p>The type of instance group for which to list the instances.</p>
    pub fn get_instance_group_types(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::InstanceGroupType>> {
        &self.instance_group_types
    }
    /// <p>The unique identifier of the instance fleet.</p>
    pub fn instance_fleet_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_fleet_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the instance fleet.</p>
    pub fn set_instance_fleet_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_fleet_id = input;
        self
    }
    /// <p>The unique identifier of the instance fleet.</p>
    pub fn get_instance_fleet_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_fleet_id
    }
    /// <p>The node type of the instance fleet. For example MASTER, CORE, or TASK.</p>
    pub fn instance_fleet_type(mut self, input: crate::types::InstanceFleetType) -> Self {
        self.instance_fleet_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The node type of the instance fleet. For example MASTER, CORE, or TASK.</p>
    pub fn set_instance_fleet_type(mut self, input: ::std::option::Option<crate::types::InstanceFleetType>) -> Self {
        self.instance_fleet_type = input;
        self
    }
    /// <p>The node type of the instance fleet. For example MASTER, CORE, or TASK.</p>
    pub fn get_instance_fleet_type(&self) -> &::std::option::Option<crate::types::InstanceFleetType> {
        &self.instance_fleet_type
    }
    /// Appends an item to `instance_states`.
    ///
    /// To override the contents of this collection use [`set_instance_states`](Self::set_instance_states).
    ///
    /// <p>A list of instance states that will filter the instances returned with this request.</p>
    pub fn instance_states(mut self, input: crate::types::InstanceState) -> Self {
        let mut v = self.instance_states.unwrap_or_default();
        v.push(input);
        self.instance_states = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of instance states that will filter the instances returned with this request.</p>
    pub fn set_instance_states(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::InstanceState>>) -> Self {
        self.instance_states = input;
        self
    }
    /// <p>A list of instance states that will filter the instances returned with this request.</p>
    pub fn get_instance_states(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::InstanceState>> {
        &self.instance_states
    }
    /// <p>The pagination token that indicates the next set of results to retrieve.</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pagination token that indicates the next set of results to retrieve.</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>The pagination token that indicates the next set of results to retrieve.</p>
    pub fn get_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.marker
    }
    /// Consumes the builder and constructs a [`ListInstancesInput`](crate::operation::list_instances::ListInstancesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_instances::ListInstancesInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_instances::ListInstancesInput {
            cluster_id: self.cluster_id,
            instance_group_id: self.instance_group_id,
            instance_group_types: self.instance_group_types,
            instance_fleet_id: self.instance_fleet_id,
            instance_fleet_type: self.instance_fleet_type,
            instance_states: self.instance_states,
            marker: self.marker,
        })
    }
}
