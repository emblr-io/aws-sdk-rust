// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides information about an Amazon Elastic Container Registry repository.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsEcrRepositoryDetails {
    /// <p>The ARN of the repository.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The image scanning configuration for a repository.</p>
    pub image_scanning_configuration: ::std::option::Option<crate::types::AwsEcrRepositoryImageScanningConfigurationDetails>,
    /// <p>The tag mutability setting for the repository. Valid values are <code>IMMUTABLE</code> or <code>MUTABLE</code>.</p>
    pub image_tag_mutability: ::std::option::Option<::std::string::String>,
    /// <p>Information about the lifecycle policy for the repository.</p>
    pub lifecycle_policy: ::std::option::Option<crate::types::AwsEcrRepositoryLifecyclePolicyDetails>,
    /// <p>The name of the repository.</p>
    pub repository_name: ::std::option::Option<::std::string::String>,
    /// <p>The text of the repository policy.</p>
    pub repository_policy_text: ::std::option::Option<::std::string::String>,
}
impl AwsEcrRepositoryDetails {
    /// <p>The ARN of the repository.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The image scanning configuration for a repository.</p>
    pub fn image_scanning_configuration(&self) -> ::std::option::Option<&crate::types::AwsEcrRepositoryImageScanningConfigurationDetails> {
        self.image_scanning_configuration.as_ref()
    }
    /// <p>The tag mutability setting for the repository. Valid values are <code>IMMUTABLE</code> or <code>MUTABLE</code>.</p>
    pub fn image_tag_mutability(&self) -> ::std::option::Option<&str> {
        self.image_tag_mutability.as_deref()
    }
    /// <p>Information about the lifecycle policy for the repository.</p>
    pub fn lifecycle_policy(&self) -> ::std::option::Option<&crate::types::AwsEcrRepositoryLifecyclePolicyDetails> {
        self.lifecycle_policy.as_ref()
    }
    /// <p>The name of the repository.</p>
    pub fn repository_name(&self) -> ::std::option::Option<&str> {
        self.repository_name.as_deref()
    }
    /// <p>The text of the repository policy.</p>
    pub fn repository_policy_text(&self) -> ::std::option::Option<&str> {
        self.repository_policy_text.as_deref()
    }
}
impl AwsEcrRepositoryDetails {
    /// Creates a new builder-style object to manufacture [`AwsEcrRepositoryDetails`](crate::types::AwsEcrRepositoryDetails).
    pub fn builder() -> crate::types::builders::AwsEcrRepositoryDetailsBuilder {
        crate::types::builders::AwsEcrRepositoryDetailsBuilder::default()
    }
}

/// A builder for [`AwsEcrRepositoryDetails`](crate::types::AwsEcrRepositoryDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsEcrRepositoryDetailsBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) image_scanning_configuration: ::std::option::Option<crate::types::AwsEcrRepositoryImageScanningConfigurationDetails>,
    pub(crate) image_tag_mutability: ::std::option::Option<::std::string::String>,
    pub(crate) lifecycle_policy: ::std::option::Option<crate::types::AwsEcrRepositoryLifecyclePolicyDetails>,
    pub(crate) repository_name: ::std::option::Option<::std::string::String>,
    pub(crate) repository_policy_text: ::std::option::Option<::std::string::String>,
}
impl AwsEcrRepositoryDetailsBuilder {
    /// <p>The ARN of the repository.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the repository.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The ARN of the repository.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The image scanning configuration for a repository.</p>
    pub fn image_scanning_configuration(mut self, input: crate::types::AwsEcrRepositoryImageScanningConfigurationDetails) -> Self {
        self.image_scanning_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The image scanning configuration for a repository.</p>
    pub fn set_image_scanning_configuration(
        mut self,
        input: ::std::option::Option<crate::types::AwsEcrRepositoryImageScanningConfigurationDetails>,
    ) -> Self {
        self.image_scanning_configuration = input;
        self
    }
    /// <p>The image scanning configuration for a repository.</p>
    pub fn get_image_scanning_configuration(&self) -> &::std::option::Option<crate::types::AwsEcrRepositoryImageScanningConfigurationDetails> {
        &self.image_scanning_configuration
    }
    /// <p>The tag mutability setting for the repository. Valid values are <code>IMMUTABLE</code> or <code>MUTABLE</code>.</p>
    pub fn image_tag_mutability(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.image_tag_mutability = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The tag mutability setting for the repository. Valid values are <code>IMMUTABLE</code> or <code>MUTABLE</code>.</p>
    pub fn set_image_tag_mutability(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.image_tag_mutability = input;
        self
    }
    /// <p>The tag mutability setting for the repository. Valid values are <code>IMMUTABLE</code> or <code>MUTABLE</code>.</p>
    pub fn get_image_tag_mutability(&self) -> &::std::option::Option<::std::string::String> {
        &self.image_tag_mutability
    }
    /// <p>Information about the lifecycle policy for the repository.</p>
    pub fn lifecycle_policy(mut self, input: crate::types::AwsEcrRepositoryLifecyclePolicyDetails) -> Self {
        self.lifecycle_policy = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the lifecycle policy for the repository.</p>
    pub fn set_lifecycle_policy(mut self, input: ::std::option::Option<crate::types::AwsEcrRepositoryLifecyclePolicyDetails>) -> Self {
        self.lifecycle_policy = input;
        self
    }
    /// <p>Information about the lifecycle policy for the repository.</p>
    pub fn get_lifecycle_policy(&self) -> &::std::option::Option<crate::types::AwsEcrRepositoryLifecyclePolicyDetails> {
        &self.lifecycle_policy
    }
    /// <p>The name of the repository.</p>
    pub fn repository_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.repository_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the repository.</p>
    pub fn set_repository_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.repository_name = input;
        self
    }
    /// <p>The name of the repository.</p>
    pub fn get_repository_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.repository_name
    }
    /// <p>The text of the repository policy.</p>
    pub fn repository_policy_text(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.repository_policy_text = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The text of the repository policy.</p>
    pub fn set_repository_policy_text(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.repository_policy_text = input;
        self
    }
    /// <p>The text of the repository policy.</p>
    pub fn get_repository_policy_text(&self) -> &::std::option::Option<::std::string::String> {
        &self.repository_policy_text
    }
    /// Consumes the builder and constructs a [`AwsEcrRepositoryDetails`](crate::types::AwsEcrRepositoryDetails).
    pub fn build(self) -> crate::types::AwsEcrRepositoryDetails {
        crate::types::AwsEcrRepositoryDetails {
            arn: self.arn,
            image_scanning_configuration: self.image_scanning_configuration,
            image_tag_mutability: self.image_tag_mutability,
            lifecycle_policy: self.lifecycle_policy,
            repository_name: self.repository_name,
            repository_policy_text: self.repository_policy_text,
        }
    }
}
