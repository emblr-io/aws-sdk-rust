// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the input of a <code>BatchGetDeploymentInstances</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchGetDeploymentInstancesInput {
    /// <p>The unique ID of a deployment.</p>
    pub deployment_id: ::std::option::Option<::std::string::String>,
    /// <p>The unique IDs of instances used in the deployment. The maximum number of instance IDs you can specify is 25.</p>
    pub instance_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl BatchGetDeploymentInstancesInput {
    /// <p>The unique ID of a deployment.</p>
    pub fn deployment_id(&self) -> ::std::option::Option<&str> {
        self.deployment_id.as_deref()
    }
    /// <p>The unique IDs of instances used in the deployment. The maximum number of instance IDs you can specify is 25.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.instance_ids.is_none()`.
    pub fn instance_ids(&self) -> &[::std::string::String] {
        self.instance_ids.as_deref().unwrap_or_default()
    }
}
impl BatchGetDeploymentInstancesInput {
    /// Creates a new builder-style object to manufacture [`BatchGetDeploymentInstancesInput`](crate::operation::batch_get_deployment_instances::BatchGetDeploymentInstancesInput).
    pub fn builder() -> crate::operation::batch_get_deployment_instances::builders::BatchGetDeploymentInstancesInputBuilder {
        crate::operation::batch_get_deployment_instances::builders::BatchGetDeploymentInstancesInputBuilder::default()
    }
}

/// A builder for [`BatchGetDeploymentInstancesInput`](crate::operation::batch_get_deployment_instances::BatchGetDeploymentInstancesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchGetDeploymentInstancesInputBuilder {
    pub(crate) deployment_id: ::std::option::Option<::std::string::String>,
    pub(crate) instance_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl BatchGetDeploymentInstancesInputBuilder {
    /// <p>The unique ID of a deployment.</p>
    /// This field is required.
    pub fn deployment_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.deployment_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ID of a deployment.</p>
    pub fn set_deployment_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.deployment_id = input;
        self
    }
    /// <p>The unique ID of a deployment.</p>
    pub fn get_deployment_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.deployment_id
    }
    /// Appends an item to `instance_ids`.
    ///
    /// To override the contents of this collection use [`set_instance_ids`](Self::set_instance_ids).
    ///
    /// <p>The unique IDs of instances used in the deployment. The maximum number of instance IDs you can specify is 25.</p>
    pub fn instance_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.instance_ids.unwrap_or_default();
        v.push(input.into());
        self.instance_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The unique IDs of instances used in the deployment. The maximum number of instance IDs you can specify is 25.</p>
    pub fn set_instance_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.instance_ids = input;
        self
    }
    /// <p>The unique IDs of instances used in the deployment. The maximum number of instance IDs you can specify is 25.</p>
    pub fn get_instance_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.instance_ids
    }
    /// Consumes the builder and constructs a [`BatchGetDeploymentInstancesInput`](crate::operation::batch_get_deployment_instances::BatchGetDeploymentInstancesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::batch_get_deployment_instances::BatchGetDeploymentInstancesInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::batch_get_deployment_instances::BatchGetDeploymentInstancesInput {
            deployment_id: self.deployment_id,
            instance_ids: self.instance_ids,
        })
    }
}
