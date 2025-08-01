// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CopyDbClusterParameterGroupOutput {
    /// <p>Contains the details of an Amazon RDS DB cluster parameter group.</p>
    /// <p>This data type is used as a response element in the <code>DescribeDBClusterParameterGroups</code> action.</p>
    pub db_cluster_parameter_group: ::std::option::Option<crate::types::DbClusterParameterGroup>,
    _request_id: Option<String>,
}
impl CopyDbClusterParameterGroupOutput {
    /// <p>Contains the details of an Amazon RDS DB cluster parameter group.</p>
    /// <p>This data type is used as a response element in the <code>DescribeDBClusterParameterGroups</code> action.</p>
    pub fn db_cluster_parameter_group(&self) -> ::std::option::Option<&crate::types::DbClusterParameterGroup> {
        self.db_cluster_parameter_group.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CopyDbClusterParameterGroupOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CopyDbClusterParameterGroupOutput {
    /// Creates a new builder-style object to manufacture [`CopyDbClusterParameterGroupOutput`](crate::operation::copy_db_cluster_parameter_group::CopyDbClusterParameterGroupOutput).
    pub fn builder() -> crate::operation::copy_db_cluster_parameter_group::builders::CopyDbClusterParameterGroupOutputBuilder {
        crate::operation::copy_db_cluster_parameter_group::builders::CopyDbClusterParameterGroupOutputBuilder::default()
    }
}

/// A builder for [`CopyDbClusterParameterGroupOutput`](crate::operation::copy_db_cluster_parameter_group::CopyDbClusterParameterGroupOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CopyDbClusterParameterGroupOutputBuilder {
    pub(crate) db_cluster_parameter_group: ::std::option::Option<crate::types::DbClusterParameterGroup>,
    _request_id: Option<String>,
}
impl CopyDbClusterParameterGroupOutputBuilder {
    /// <p>Contains the details of an Amazon RDS DB cluster parameter group.</p>
    /// <p>This data type is used as a response element in the <code>DescribeDBClusterParameterGroups</code> action.</p>
    pub fn db_cluster_parameter_group(mut self, input: crate::types::DbClusterParameterGroup) -> Self {
        self.db_cluster_parameter_group = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains the details of an Amazon RDS DB cluster parameter group.</p>
    /// <p>This data type is used as a response element in the <code>DescribeDBClusterParameterGroups</code> action.</p>
    pub fn set_db_cluster_parameter_group(mut self, input: ::std::option::Option<crate::types::DbClusterParameterGroup>) -> Self {
        self.db_cluster_parameter_group = input;
        self
    }
    /// <p>Contains the details of an Amazon RDS DB cluster parameter group.</p>
    /// <p>This data type is used as a response element in the <code>DescribeDBClusterParameterGroups</code> action.</p>
    pub fn get_db_cluster_parameter_group(&self) -> &::std::option::Option<crate::types::DbClusterParameterGroup> {
        &self.db_cluster_parameter_group
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CopyDbClusterParameterGroupOutput`](crate::operation::copy_db_cluster_parameter_group::CopyDbClusterParameterGroupOutput).
    pub fn build(self) -> crate::operation::copy_db_cluster_parameter_group::CopyDbClusterParameterGroupOutput {
        crate::operation::copy_db_cluster_parameter_group::CopyDbClusterParameterGroupOutput {
            db_cluster_parameter_group: self.db_cluster_parameter_group,
            _request_id: self._request_id,
        }
    }
}
