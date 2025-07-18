// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a request to activate or deactivate the role that you can use to grant an Amazon Lightsail container service access to Amazon Elastic Container Registry (Amazon ECR) private repositories.</p>
/// <p>When activated, Lightsail creates an Identity and Access Management (IAM) role for the specified Lightsail container service. You can use the ARN of the role to create a trust relationship between your Lightsail container service and an Amazon ECR private repository in your Amazon Web Services account. This allows your container service to pull images from Amazon ECR private repositories. For more information, see <a href="https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-container-service-ecr-private-repo-access">Configuring access to an Amazon ECR private repository for an Amazon Lightsail container service</a> in the <i>Amazon Lightsail Developer Guide</i>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ContainerServiceEcrImagePullerRoleRequest {
    /// <p>A Boolean value that indicates whether to activate the role.</p>
    pub is_active: ::std::option::Option<bool>,
}
impl ContainerServiceEcrImagePullerRoleRequest {
    /// <p>A Boolean value that indicates whether to activate the role.</p>
    pub fn is_active(&self) -> ::std::option::Option<bool> {
        self.is_active
    }
}
impl ContainerServiceEcrImagePullerRoleRequest {
    /// Creates a new builder-style object to manufacture [`ContainerServiceEcrImagePullerRoleRequest`](crate::types::ContainerServiceEcrImagePullerRoleRequest).
    pub fn builder() -> crate::types::builders::ContainerServiceEcrImagePullerRoleRequestBuilder {
        crate::types::builders::ContainerServiceEcrImagePullerRoleRequestBuilder::default()
    }
}

/// A builder for [`ContainerServiceEcrImagePullerRoleRequest`](crate::types::ContainerServiceEcrImagePullerRoleRequest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ContainerServiceEcrImagePullerRoleRequestBuilder {
    pub(crate) is_active: ::std::option::Option<bool>,
}
impl ContainerServiceEcrImagePullerRoleRequestBuilder {
    /// <p>A Boolean value that indicates whether to activate the role.</p>
    pub fn is_active(mut self, input: bool) -> Self {
        self.is_active = ::std::option::Option::Some(input);
        self
    }
    /// <p>A Boolean value that indicates whether to activate the role.</p>
    pub fn set_is_active(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_active = input;
        self
    }
    /// <p>A Boolean value that indicates whether to activate the role.</p>
    pub fn get_is_active(&self) -> &::std::option::Option<bool> {
        &self.is_active
    }
    /// Consumes the builder and constructs a [`ContainerServiceEcrImagePullerRoleRequest`](crate::types::ContainerServiceEcrImagePullerRoleRequest).
    pub fn build(self) -> crate::types::ContainerServiceEcrImagePullerRoleRequest {
        crate::types::ContainerServiceEcrImagePullerRoleRequest { is_active: self.is_active }
    }
}
