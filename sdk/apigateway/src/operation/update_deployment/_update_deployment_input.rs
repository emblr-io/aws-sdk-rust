// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Requests API Gateway to change information about a Deployment resource.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateDeploymentInput {
    /// <p>The string identifier of the associated RestApi.</p>
    pub rest_api_id: ::std::option::Option<::std::string::String>,
    /// <p>The replacement identifier for the Deployment resource to change information about.</p>
    pub deployment_id: ::std::option::Option<::std::string::String>,
    /// <p>For more information about supported patch operations, see <a href="https://docs.aws.amazon.com/apigateway/latest/api/patch-operations.html">Patch Operations</a>.</p>
    pub patch_operations: ::std::option::Option<::std::vec::Vec<crate::types::PatchOperation>>,
}
impl UpdateDeploymentInput {
    /// <p>The string identifier of the associated RestApi.</p>
    pub fn rest_api_id(&self) -> ::std::option::Option<&str> {
        self.rest_api_id.as_deref()
    }
    /// <p>The replacement identifier for the Deployment resource to change information about.</p>
    pub fn deployment_id(&self) -> ::std::option::Option<&str> {
        self.deployment_id.as_deref()
    }
    /// <p>For more information about supported patch operations, see <a href="https://docs.aws.amazon.com/apigateway/latest/api/patch-operations.html">Patch Operations</a>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.patch_operations.is_none()`.
    pub fn patch_operations(&self) -> &[crate::types::PatchOperation] {
        self.patch_operations.as_deref().unwrap_or_default()
    }
}
impl UpdateDeploymentInput {
    /// Creates a new builder-style object to manufacture [`UpdateDeploymentInput`](crate::operation::update_deployment::UpdateDeploymentInput).
    pub fn builder() -> crate::operation::update_deployment::builders::UpdateDeploymentInputBuilder {
        crate::operation::update_deployment::builders::UpdateDeploymentInputBuilder::default()
    }
}

/// A builder for [`UpdateDeploymentInput`](crate::operation::update_deployment::UpdateDeploymentInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateDeploymentInputBuilder {
    pub(crate) rest_api_id: ::std::option::Option<::std::string::String>,
    pub(crate) deployment_id: ::std::option::Option<::std::string::String>,
    pub(crate) patch_operations: ::std::option::Option<::std::vec::Vec<crate::types::PatchOperation>>,
}
impl UpdateDeploymentInputBuilder {
    /// <p>The string identifier of the associated RestApi.</p>
    /// This field is required.
    pub fn rest_api_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.rest_api_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The string identifier of the associated RestApi.</p>
    pub fn set_rest_api_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.rest_api_id = input;
        self
    }
    /// <p>The string identifier of the associated RestApi.</p>
    pub fn get_rest_api_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.rest_api_id
    }
    /// <p>The replacement identifier for the Deployment resource to change information about.</p>
    /// This field is required.
    pub fn deployment_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.deployment_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The replacement identifier for the Deployment resource to change information about.</p>
    pub fn set_deployment_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.deployment_id = input;
        self
    }
    /// <p>The replacement identifier for the Deployment resource to change information about.</p>
    pub fn get_deployment_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.deployment_id
    }
    /// Appends an item to `patch_operations`.
    ///
    /// To override the contents of this collection use [`set_patch_operations`](Self::set_patch_operations).
    ///
    /// <p>For more information about supported patch operations, see <a href="https://docs.aws.amazon.com/apigateway/latest/api/patch-operations.html">Patch Operations</a>.</p>
    pub fn patch_operations(mut self, input: crate::types::PatchOperation) -> Self {
        let mut v = self.patch_operations.unwrap_or_default();
        v.push(input);
        self.patch_operations = ::std::option::Option::Some(v);
        self
    }
    /// <p>For more information about supported patch operations, see <a href="https://docs.aws.amazon.com/apigateway/latest/api/patch-operations.html">Patch Operations</a>.</p>
    pub fn set_patch_operations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PatchOperation>>) -> Self {
        self.patch_operations = input;
        self
    }
    /// <p>For more information about supported patch operations, see <a href="https://docs.aws.amazon.com/apigateway/latest/api/patch-operations.html">Patch Operations</a>.</p>
    pub fn get_patch_operations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PatchOperation>> {
        &self.patch_operations
    }
    /// Consumes the builder and constructs a [`UpdateDeploymentInput`](crate::operation::update_deployment::UpdateDeploymentInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_deployment::UpdateDeploymentInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_deployment::UpdateDeploymentInput {
            rest_api_id: self.rest_api_id,
            deployment_id: self.deployment_id,
            patch_operations: self.patch_operations,
        })
    }
}
