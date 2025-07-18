// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeFleetDeploymentOutput {
    /// <p>The requested deployment information.</p>
    pub fleet_deployment: ::std::option::Option<crate::types::FleetDeployment>,
    /// <p>If the deployment is for a multi-location fleet, the requests returns the deployment status in each fleet location.</p>
    pub locational_deployments: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::LocationalDeployment>>,
    _request_id: Option<String>,
}
impl DescribeFleetDeploymentOutput {
    /// <p>The requested deployment information.</p>
    pub fn fleet_deployment(&self) -> ::std::option::Option<&crate::types::FleetDeployment> {
        self.fleet_deployment.as_ref()
    }
    /// <p>If the deployment is for a multi-location fleet, the requests returns the deployment status in each fleet location.</p>
    pub fn locational_deployments(
        &self,
    ) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, crate::types::LocationalDeployment>> {
        self.locational_deployments.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeFleetDeploymentOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeFleetDeploymentOutput {
    /// Creates a new builder-style object to manufacture [`DescribeFleetDeploymentOutput`](crate::operation::describe_fleet_deployment::DescribeFleetDeploymentOutput).
    pub fn builder() -> crate::operation::describe_fleet_deployment::builders::DescribeFleetDeploymentOutputBuilder {
        crate::operation::describe_fleet_deployment::builders::DescribeFleetDeploymentOutputBuilder::default()
    }
}

/// A builder for [`DescribeFleetDeploymentOutput`](crate::operation::describe_fleet_deployment::DescribeFleetDeploymentOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeFleetDeploymentOutputBuilder {
    pub(crate) fleet_deployment: ::std::option::Option<crate::types::FleetDeployment>,
    pub(crate) locational_deployments: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::LocationalDeployment>>,
    _request_id: Option<String>,
}
impl DescribeFleetDeploymentOutputBuilder {
    /// <p>The requested deployment information.</p>
    pub fn fleet_deployment(mut self, input: crate::types::FleetDeployment) -> Self {
        self.fleet_deployment = ::std::option::Option::Some(input);
        self
    }
    /// <p>The requested deployment information.</p>
    pub fn set_fleet_deployment(mut self, input: ::std::option::Option<crate::types::FleetDeployment>) -> Self {
        self.fleet_deployment = input;
        self
    }
    /// <p>The requested deployment information.</p>
    pub fn get_fleet_deployment(&self) -> &::std::option::Option<crate::types::FleetDeployment> {
        &self.fleet_deployment
    }
    /// Adds a key-value pair to `locational_deployments`.
    ///
    /// To override the contents of this collection use [`set_locational_deployments`](Self::set_locational_deployments).
    ///
    /// <p>If the deployment is for a multi-location fleet, the requests returns the deployment status in each fleet location.</p>
    pub fn locational_deployments(mut self, k: impl ::std::convert::Into<::std::string::String>, v: crate::types::LocationalDeployment) -> Self {
        let mut hash_map = self.locational_deployments.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.locational_deployments = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>If the deployment is for a multi-location fleet, the requests returns the deployment status in each fleet location.</p>
    pub fn set_locational_deployments(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::LocationalDeployment>>,
    ) -> Self {
        self.locational_deployments = input;
        self
    }
    /// <p>If the deployment is for a multi-location fleet, the requests returns the deployment status in each fleet location.</p>
    pub fn get_locational_deployments(
        &self,
    ) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::LocationalDeployment>> {
        &self.locational_deployments
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeFleetDeploymentOutput`](crate::operation::describe_fleet_deployment::DescribeFleetDeploymentOutput).
    pub fn build(self) -> crate::operation::describe_fleet_deployment::DescribeFleetDeploymentOutput {
        crate::operation::describe_fleet_deployment::DescribeFleetDeploymentOutput {
            fleet_deployment: self.fleet_deployment,
            locational_deployments: self.locational_deployments,
            _request_id: self._request_id,
        }
    }
}
