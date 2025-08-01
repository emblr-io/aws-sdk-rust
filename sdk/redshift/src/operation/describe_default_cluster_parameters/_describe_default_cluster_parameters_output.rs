// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeDefaultClusterParametersOutput {
    /// <p>Describes the default cluster parameters for a parameter group family.</p>
    pub default_cluster_parameters: ::std::option::Option<crate::types::DefaultClusterParameters>,
    _request_id: Option<String>,
}
impl DescribeDefaultClusterParametersOutput {
    /// <p>Describes the default cluster parameters for a parameter group family.</p>
    pub fn default_cluster_parameters(&self) -> ::std::option::Option<&crate::types::DefaultClusterParameters> {
        self.default_cluster_parameters.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeDefaultClusterParametersOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeDefaultClusterParametersOutput {
    /// Creates a new builder-style object to manufacture [`DescribeDefaultClusterParametersOutput`](crate::operation::describe_default_cluster_parameters::DescribeDefaultClusterParametersOutput).
    pub fn builder() -> crate::operation::describe_default_cluster_parameters::builders::DescribeDefaultClusterParametersOutputBuilder {
        crate::operation::describe_default_cluster_parameters::builders::DescribeDefaultClusterParametersOutputBuilder::default()
    }
}

/// A builder for [`DescribeDefaultClusterParametersOutput`](crate::operation::describe_default_cluster_parameters::DescribeDefaultClusterParametersOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeDefaultClusterParametersOutputBuilder {
    pub(crate) default_cluster_parameters: ::std::option::Option<crate::types::DefaultClusterParameters>,
    _request_id: Option<String>,
}
impl DescribeDefaultClusterParametersOutputBuilder {
    /// <p>Describes the default cluster parameters for a parameter group family.</p>
    pub fn default_cluster_parameters(mut self, input: crate::types::DefaultClusterParameters) -> Self {
        self.default_cluster_parameters = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes the default cluster parameters for a parameter group family.</p>
    pub fn set_default_cluster_parameters(mut self, input: ::std::option::Option<crate::types::DefaultClusterParameters>) -> Self {
        self.default_cluster_parameters = input;
        self
    }
    /// <p>Describes the default cluster parameters for a parameter group family.</p>
    pub fn get_default_cluster_parameters(&self) -> &::std::option::Option<crate::types::DefaultClusterParameters> {
        &self.default_cluster_parameters
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeDefaultClusterParametersOutput`](crate::operation::describe_default_cluster_parameters::DescribeDefaultClusterParametersOutput).
    pub fn build(self) -> crate::operation::describe_default_cluster_parameters::DescribeDefaultClusterParametersOutput {
        crate::operation::describe_default_cluster_parameters::DescribeDefaultClusterParametersOutput {
            default_cluster_parameters: self.default_cluster_parameters,
            _request_id: self._request_id,
        }
    }
}
