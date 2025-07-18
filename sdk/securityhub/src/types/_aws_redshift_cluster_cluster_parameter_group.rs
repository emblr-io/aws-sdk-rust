// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A cluster parameter group that is associated with an Amazon Redshift cluster.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsRedshiftClusterClusterParameterGroup {
    /// <p>The list of parameter statuses.</p>
    pub cluster_parameter_status_list: ::std::option::Option<::std::vec::Vec<crate::types::AwsRedshiftClusterClusterParameterStatus>>,
    /// <p>The status of updates to the parameters.</p>
    pub parameter_apply_status: ::std::option::Option<::std::string::String>,
    /// <p>The name of the parameter group.</p>
    pub parameter_group_name: ::std::option::Option<::std::string::String>,
}
impl AwsRedshiftClusterClusterParameterGroup {
    /// <p>The list of parameter statuses.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.cluster_parameter_status_list.is_none()`.
    pub fn cluster_parameter_status_list(&self) -> &[crate::types::AwsRedshiftClusterClusterParameterStatus] {
        self.cluster_parameter_status_list.as_deref().unwrap_or_default()
    }
    /// <p>The status of updates to the parameters.</p>
    pub fn parameter_apply_status(&self) -> ::std::option::Option<&str> {
        self.parameter_apply_status.as_deref()
    }
    /// <p>The name of the parameter group.</p>
    pub fn parameter_group_name(&self) -> ::std::option::Option<&str> {
        self.parameter_group_name.as_deref()
    }
}
impl AwsRedshiftClusterClusterParameterGroup {
    /// Creates a new builder-style object to manufacture [`AwsRedshiftClusterClusterParameterGroup`](crate::types::AwsRedshiftClusterClusterParameterGroup).
    pub fn builder() -> crate::types::builders::AwsRedshiftClusterClusterParameterGroupBuilder {
        crate::types::builders::AwsRedshiftClusterClusterParameterGroupBuilder::default()
    }
}

/// A builder for [`AwsRedshiftClusterClusterParameterGroup`](crate::types::AwsRedshiftClusterClusterParameterGroup).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsRedshiftClusterClusterParameterGroupBuilder {
    pub(crate) cluster_parameter_status_list: ::std::option::Option<::std::vec::Vec<crate::types::AwsRedshiftClusterClusterParameterStatus>>,
    pub(crate) parameter_apply_status: ::std::option::Option<::std::string::String>,
    pub(crate) parameter_group_name: ::std::option::Option<::std::string::String>,
}
impl AwsRedshiftClusterClusterParameterGroupBuilder {
    /// Appends an item to `cluster_parameter_status_list`.
    ///
    /// To override the contents of this collection use [`set_cluster_parameter_status_list`](Self::set_cluster_parameter_status_list).
    ///
    /// <p>The list of parameter statuses.</p>
    pub fn cluster_parameter_status_list(mut self, input: crate::types::AwsRedshiftClusterClusterParameterStatus) -> Self {
        let mut v = self.cluster_parameter_status_list.unwrap_or_default();
        v.push(input);
        self.cluster_parameter_status_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of parameter statuses.</p>
    pub fn set_cluster_parameter_status_list(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::AwsRedshiftClusterClusterParameterStatus>>,
    ) -> Self {
        self.cluster_parameter_status_list = input;
        self
    }
    /// <p>The list of parameter statuses.</p>
    pub fn get_cluster_parameter_status_list(
        &self,
    ) -> &::std::option::Option<::std::vec::Vec<crate::types::AwsRedshiftClusterClusterParameterStatus>> {
        &self.cluster_parameter_status_list
    }
    /// <p>The status of updates to the parameters.</p>
    pub fn parameter_apply_status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.parameter_apply_status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The status of updates to the parameters.</p>
    pub fn set_parameter_apply_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.parameter_apply_status = input;
        self
    }
    /// <p>The status of updates to the parameters.</p>
    pub fn get_parameter_apply_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.parameter_apply_status
    }
    /// <p>The name of the parameter group.</p>
    pub fn parameter_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.parameter_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the parameter group.</p>
    pub fn set_parameter_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.parameter_group_name = input;
        self
    }
    /// <p>The name of the parameter group.</p>
    pub fn get_parameter_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.parameter_group_name
    }
    /// Consumes the builder and constructs a [`AwsRedshiftClusterClusterParameterGroup`](crate::types::AwsRedshiftClusterClusterParameterGroup).
    pub fn build(self) -> crate::types::AwsRedshiftClusterClusterParameterGroup {
        crate::types::AwsRedshiftClusterClusterParameterGroup {
            cluster_parameter_status_list: self.cluster_parameter_status_list,
            parameter_apply_status: self.parameter_apply_status,
            parameter_group_name: self.parameter_group_name,
        }
    }
}
