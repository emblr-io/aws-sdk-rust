// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The details of the repository creation template associated with the request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RepositoryCreationTemplate {
    /// <p>The repository namespace prefix associated with the repository creation template.</p>
    pub prefix: ::std::option::Option<::std::string::String>,
    /// <p>The description associated with the repository creation template.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The encryption configuration associated with the repository creation template.</p>
    pub encryption_configuration: ::std::option::Option<crate::types::EncryptionConfigurationForRepositoryCreationTemplate>,
    /// <p>The metadata to apply to the repository to help you categorize and organize. Each tag consists of a key and an optional value, both of which you define. Tag keys can have a maximum character length of 128 characters, and tag values can have a maximum length of 256 characters.</p>
    pub resource_tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    /// <p>The tag mutability setting for the repository. If this parameter is omitted, the default setting of <code>MUTABLE</code> will be used which will allow image tags to be overwritten. If <code>IMMUTABLE</code> is specified, all image tags within the repository will be immutable which will prevent them from being overwritten.</p>
    pub image_tag_mutability: ::std::option::Option<crate::types::ImageTagMutability>,
    /// <p>The repository policy to apply to repositories created using the template. A repository policy is a permissions policy associated with a repository to control access permissions.</p>
    pub repository_policy: ::std::option::Option<::std::string::String>,
    /// <p>The lifecycle policy to use for repositories created using the template.</p>
    pub lifecycle_policy: ::std::option::Option<::std::string::String>,
    /// <p>A list of enumerable Strings representing the repository creation scenarios that this template will apply towards. The two supported scenarios are PULL_THROUGH_CACHE and REPLICATION</p>
    pub applied_for: ::std::option::Option<::std::vec::Vec<crate::types::RctAppliedFor>>,
    /// <p>The ARN of the role to be assumed by Amazon ECR. Amazon ECR will assume your supplied role when the customRoleArn is specified. When this field isn't specified, Amazon ECR will use the service-linked role for the repository creation template.</p>
    pub custom_role_arn: ::std::option::Option<::std::string::String>,
    /// <p>The date and time, in JavaScript date format, when the repository creation template was created.</p>
    pub created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date and time, in JavaScript date format, when the repository creation template was last updated.</p>
    pub updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl RepositoryCreationTemplate {
    /// <p>The repository namespace prefix associated with the repository creation template.</p>
    pub fn prefix(&self) -> ::std::option::Option<&str> {
        self.prefix.as_deref()
    }
    /// <p>The description associated with the repository creation template.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The encryption configuration associated with the repository creation template.</p>
    pub fn encryption_configuration(&self) -> ::std::option::Option<&crate::types::EncryptionConfigurationForRepositoryCreationTemplate> {
        self.encryption_configuration.as_ref()
    }
    /// <p>The metadata to apply to the repository to help you categorize and organize. Each tag consists of a key and an optional value, both of which you define. Tag keys can have a maximum character length of 128 characters, and tag values can have a maximum length of 256 characters.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.resource_tags.is_none()`.
    pub fn resource_tags(&self) -> &[crate::types::Tag] {
        self.resource_tags.as_deref().unwrap_or_default()
    }
    /// <p>The tag mutability setting for the repository. If this parameter is omitted, the default setting of <code>MUTABLE</code> will be used which will allow image tags to be overwritten. If <code>IMMUTABLE</code> is specified, all image tags within the repository will be immutable which will prevent them from being overwritten.</p>
    pub fn image_tag_mutability(&self) -> ::std::option::Option<&crate::types::ImageTagMutability> {
        self.image_tag_mutability.as_ref()
    }
    /// <p>The repository policy to apply to repositories created using the template. A repository policy is a permissions policy associated with a repository to control access permissions.</p>
    pub fn repository_policy(&self) -> ::std::option::Option<&str> {
        self.repository_policy.as_deref()
    }
    /// <p>The lifecycle policy to use for repositories created using the template.</p>
    pub fn lifecycle_policy(&self) -> ::std::option::Option<&str> {
        self.lifecycle_policy.as_deref()
    }
    /// <p>A list of enumerable Strings representing the repository creation scenarios that this template will apply towards. The two supported scenarios are PULL_THROUGH_CACHE and REPLICATION</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.applied_for.is_none()`.
    pub fn applied_for(&self) -> &[crate::types::RctAppliedFor] {
        self.applied_for.as_deref().unwrap_or_default()
    }
    /// <p>The ARN of the role to be assumed by Amazon ECR. Amazon ECR will assume your supplied role when the customRoleArn is specified. When this field isn't specified, Amazon ECR will use the service-linked role for the repository creation template.</p>
    pub fn custom_role_arn(&self) -> ::std::option::Option<&str> {
        self.custom_role_arn.as_deref()
    }
    /// <p>The date and time, in JavaScript date format, when the repository creation template was created.</p>
    pub fn created_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_at.as_ref()
    }
    /// <p>The date and time, in JavaScript date format, when the repository creation template was last updated.</p>
    pub fn updated_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.updated_at.as_ref()
    }
}
impl RepositoryCreationTemplate {
    /// Creates a new builder-style object to manufacture [`RepositoryCreationTemplate`](crate::types::RepositoryCreationTemplate).
    pub fn builder() -> crate::types::builders::RepositoryCreationTemplateBuilder {
        crate::types::builders::RepositoryCreationTemplateBuilder::default()
    }
}

/// A builder for [`RepositoryCreationTemplate`](crate::types::RepositoryCreationTemplate).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RepositoryCreationTemplateBuilder {
    pub(crate) prefix: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) encryption_configuration: ::std::option::Option<crate::types::EncryptionConfigurationForRepositoryCreationTemplate>,
    pub(crate) resource_tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    pub(crate) image_tag_mutability: ::std::option::Option<crate::types::ImageTagMutability>,
    pub(crate) repository_policy: ::std::option::Option<::std::string::String>,
    pub(crate) lifecycle_policy: ::std::option::Option<::std::string::String>,
    pub(crate) applied_for: ::std::option::Option<::std::vec::Vec<crate::types::RctAppliedFor>>,
    pub(crate) custom_role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl RepositoryCreationTemplateBuilder {
    /// <p>The repository namespace prefix associated with the repository creation template.</p>
    pub fn prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The repository namespace prefix associated with the repository creation template.</p>
    pub fn set_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.prefix = input;
        self
    }
    /// <p>The repository namespace prefix associated with the repository creation template.</p>
    pub fn get_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.prefix
    }
    /// <p>The description associated with the repository creation template.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description associated with the repository creation template.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description associated with the repository creation template.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The encryption configuration associated with the repository creation template.</p>
    pub fn encryption_configuration(mut self, input: crate::types::EncryptionConfigurationForRepositoryCreationTemplate) -> Self {
        self.encryption_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The encryption configuration associated with the repository creation template.</p>
    pub fn set_encryption_configuration(
        mut self,
        input: ::std::option::Option<crate::types::EncryptionConfigurationForRepositoryCreationTemplate>,
    ) -> Self {
        self.encryption_configuration = input;
        self
    }
    /// <p>The encryption configuration associated with the repository creation template.</p>
    pub fn get_encryption_configuration(&self) -> &::std::option::Option<crate::types::EncryptionConfigurationForRepositoryCreationTemplate> {
        &self.encryption_configuration
    }
    /// Appends an item to `resource_tags`.
    ///
    /// To override the contents of this collection use [`set_resource_tags`](Self::set_resource_tags).
    ///
    /// <p>The metadata to apply to the repository to help you categorize and organize. Each tag consists of a key and an optional value, both of which you define. Tag keys can have a maximum character length of 128 characters, and tag values can have a maximum length of 256 characters.</p>
    pub fn resource_tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.resource_tags.unwrap_or_default();
        v.push(input);
        self.resource_tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The metadata to apply to the repository to help you categorize and organize. Each tag consists of a key and an optional value, both of which you define. Tag keys can have a maximum character length of 128 characters, and tag values can have a maximum length of 256 characters.</p>
    pub fn set_resource_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.resource_tags = input;
        self
    }
    /// <p>The metadata to apply to the repository to help you categorize and organize. Each tag consists of a key and an optional value, both of which you define. Tag keys can have a maximum character length of 128 characters, and tag values can have a maximum length of 256 characters.</p>
    pub fn get_resource_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.resource_tags
    }
    /// <p>The tag mutability setting for the repository. If this parameter is omitted, the default setting of <code>MUTABLE</code> will be used which will allow image tags to be overwritten. If <code>IMMUTABLE</code> is specified, all image tags within the repository will be immutable which will prevent them from being overwritten.</p>
    pub fn image_tag_mutability(mut self, input: crate::types::ImageTagMutability) -> Self {
        self.image_tag_mutability = ::std::option::Option::Some(input);
        self
    }
    /// <p>The tag mutability setting for the repository. If this parameter is omitted, the default setting of <code>MUTABLE</code> will be used which will allow image tags to be overwritten. If <code>IMMUTABLE</code> is specified, all image tags within the repository will be immutable which will prevent them from being overwritten.</p>
    pub fn set_image_tag_mutability(mut self, input: ::std::option::Option<crate::types::ImageTagMutability>) -> Self {
        self.image_tag_mutability = input;
        self
    }
    /// <p>The tag mutability setting for the repository. If this parameter is omitted, the default setting of <code>MUTABLE</code> will be used which will allow image tags to be overwritten. If <code>IMMUTABLE</code> is specified, all image tags within the repository will be immutable which will prevent them from being overwritten.</p>
    pub fn get_image_tag_mutability(&self) -> &::std::option::Option<crate::types::ImageTagMutability> {
        &self.image_tag_mutability
    }
    /// <p>The repository policy to apply to repositories created using the template. A repository policy is a permissions policy associated with a repository to control access permissions.</p>
    pub fn repository_policy(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.repository_policy = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The repository policy to apply to repositories created using the template. A repository policy is a permissions policy associated with a repository to control access permissions.</p>
    pub fn set_repository_policy(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.repository_policy = input;
        self
    }
    /// <p>The repository policy to apply to repositories created using the template. A repository policy is a permissions policy associated with a repository to control access permissions.</p>
    pub fn get_repository_policy(&self) -> &::std::option::Option<::std::string::String> {
        &self.repository_policy
    }
    /// <p>The lifecycle policy to use for repositories created using the template.</p>
    pub fn lifecycle_policy(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.lifecycle_policy = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The lifecycle policy to use for repositories created using the template.</p>
    pub fn set_lifecycle_policy(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.lifecycle_policy = input;
        self
    }
    /// <p>The lifecycle policy to use for repositories created using the template.</p>
    pub fn get_lifecycle_policy(&self) -> &::std::option::Option<::std::string::String> {
        &self.lifecycle_policy
    }
    /// Appends an item to `applied_for`.
    ///
    /// To override the contents of this collection use [`set_applied_for`](Self::set_applied_for).
    ///
    /// <p>A list of enumerable Strings representing the repository creation scenarios that this template will apply towards. The two supported scenarios are PULL_THROUGH_CACHE and REPLICATION</p>
    pub fn applied_for(mut self, input: crate::types::RctAppliedFor) -> Self {
        let mut v = self.applied_for.unwrap_or_default();
        v.push(input);
        self.applied_for = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of enumerable Strings representing the repository creation scenarios that this template will apply towards. The two supported scenarios are PULL_THROUGH_CACHE and REPLICATION</p>
    pub fn set_applied_for(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::RctAppliedFor>>) -> Self {
        self.applied_for = input;
        self
    }
    /// <p>A list of enumerable Strings representing the repository creation scenarios that this template will apply towards. The two supported scenarios are PULL_THROUGH_CACHE and REPLICATION</p>
    pub fn get_applied_for(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::RctAppliedFor>> {
        &self.applied_for
    }
    /// <p>The ARN of the role to be assumed by Amazon ECR. Amazon ECR will assume your supplied role when the customRoleArn is specified. When this field isn't specified, Amazon ECR will use the service-linked role for the repository creation template.</p>
    pub fn custom_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.custom_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the role to be assumed by Amazon ECR. Amazon ECR will assume your supplied role when the customRoleArn is specified. When this field isn't specified, Amazon ECR will use the service-linked role for the repository creation template.</p>
    pub fn set_custom_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.custom_role_arn = input;
        self
    }
    /// <p>The ARN of the role to be assumed by Amazon ECR. Amazon ECR will assume your supplied role when the customRoleArn is specified. When this field isn't specified, Amazon ECR will use the service-linked role for the repository creation template.</p>
    pub fn get_custom_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.custom_role_arn
    }
    /// <p>The date and time, in JavaScript date format, when the repository creation template was created.</p>
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time, in JavaScript date format, when the repository creation template was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The date and time, in JavaScript date format, when the repository creation template was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The date and time, in JavaScript date format, when the repository creation template was last updated.</p>
    pub fn updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time, in JavaScript date format, when the repository creation template was last updated.</p>
    pub fn set_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.updated_at = input;
        self
    }
    /// <p>The date and time, in JavaScript date format, when the repository creation template was last updated.</p>
    pub fn get_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.updated_at
    }
    /// Consumes the builder and constructs a [`RepositoryCreationTemplate`](crate::types::RepositoryCreationTemplate).
    pub fn build(self) -> crate::types::RepositoryCreationTemplate {
        crate::types::RepositoryCreationTemplate {
            prefix: self.prefix,
            description: self.description,
            encryption_configuration: self.encryption_configuration,
            resource_tags: self.resource_tags,
            image_tag_mutability: self.image_tag_mutability,
            repository_policy: self.repository_policy,
            lifecycle_policy: self.lifecycle_policy,
            applied_for: self.applied_for,
            custom_role_arn: self.custom_role_arn,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}
