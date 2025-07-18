// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StopEdgeDeploymentStageInput {
    /// <p>The name of the edge deployment plan to stop.</p>
    pub edge_deployment_plan_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the stage to stop.</p>
    pub stage_name: ::std::option::Option<::std::string::String>,
}
impl StopEdgeDeploymentStageInput {
    /// <p>The name of the edge deployment plan to stop.</p>
    pub fn edge_deployment_plan_name(&self) -> ::std::option::Option<&str> {
        self.edge_deployment_plan_name.as_deref()
    }
    /// <p>The name of the stage to stop.</p>
    pub fn stage_name(&self) -> ::std::option::Option<&str> {
        self.stage_name.as_deref()
    }
}
impl StopEdgeDeploymentStageInput {
    /// Creates a new builder-style object to manufacture [`StopEdgeDeploymentStageInput`](crate::operation::stop_edge_deployment_stage::StopEdgeDeploymentStageInput).
    pub fn builder() -> crate::operation::stop_edge_deployment_stage::builders::StopEdgeDeploymentStageInputBuilder {
        crate::operation::stop_edge_deployment_stage::builders::StopEdgeDeploymentStageInputBuilder::default()
    }
}

/// A builder for [`StopEdgeDeploymentStageInput`](crate::operation::stop_edge_deployment_stage::StopEdgeDeploymentStageInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StopEdgeDeploymentStageInputBuilder {
    pub(crate) edge_deployment_plan_name: ::std::option::Option<::std::string::String>,
    pub(crate) stage_name: ::std::option::Option<::std::string::String>,
}
impl StopEdgeDeploymentStageInputBuilder {
    /// <p>The name of the edge deployment plan to stop.</p>
    /// This field is required.
    pub fn edge_deployment_plan_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.edge_deployment_plan_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the edge deployment plan to stop.</p>
    pub fn set_edge_deployment_plan_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.edge_deployment_plan_name = input;
        self
    }
    /// <p>The name of the edge deployment plan to stop.</p>
    pub fn get_edge_deployment_plan_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.edge_deployment_plan_name
    }
    /// <p>The name of the stage to stop.</p>
    /// This field is required.
    pub fn stage_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stage_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the stage to stop.</p>
    pub fn set_stage_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stage_name = input;
        self
    }
    /// <p>The name of the stage to stop.</p>
    pub fn get_stage_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.stage_name
    }
    /// Consumes the builder and constructs a [`StopEdgeDeploymentStageInput`](crate::operation::stop_edge_deployment_stage::StopEdgeDeploymentStageInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::stop_edge_deployment_stage::StopEdgeDeploymentStageInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::stop_edge_deployment_stage::StopEdgeDeploymentStageInput {
            edge_deployment_plan_name: self.edge_deployment_plan_name,
            stage_name: self.stage_name,
        })
    }
}
