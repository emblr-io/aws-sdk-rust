// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The details of a pull through cache rule.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PullThroughCacheRule {
    /// <p>The Amazon ECR repository prefix associated with the pull through cache rule.</p>
    pub ecr_repository_prefix: ::std::option::Option<::std::string::String>,
    /// <p>The upstream registry URL associated with the pull through cache rule.</p>
    pub upstream_registry_url: ::std::option::Option<::std::string::String>,
    /// <p>The date and time the pull through cache was created.</p>
    pub created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The Amazon Web Services account ID associated with the registry the pull through cache rule is associated with.</p>
    pub registry_id: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the Secrets Manager secret associated with the pull through cache rule.</p>
    pub credential_arn: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the IAM role associated with the pull through cache rule.</p>
    pub custom_role_arn: ::std::option::Option<::std::string::String>,
    /// <p>The upstream repository prefix associated with the pull through cache rule.</p>
    pub upstream_repository_prefix: ::std::option::Option<::std::string::String>,
    /// <p>The name of the upstream source registry associated with the pull through cache rule.</p>
    pub upstream_registry: ::std::option::Option<crate::types::UpstreamRegistry>,
    /// <p>The date and time, in JavaScript date format, when the pull through cache rule was last updated.</p>
    pub updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl PullThroughCacheRule {
    /// <p>The Amazon ECR repository prefix associated with the pull through cache rule.</p>
    pub fn ecr_repository_prefix(&self) -> ::std::option::Option<&str> {
        self.ecr_repository_prefix.as_deref()
    }
    /// <p>The upstream registry URL associated with the pull through cache rule.</p>
    pub fn upstream_registry_url(&self) -> ::std::option::Option<&str> {
        self.upstream_registry_url.as_deref()
    }
    /// <p>The date and time the pull through cache was created.</p>
    pub fn created_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_at.as_ref()
    }
    /// <p>The Amazon Web Services account ID associated with the registry the pull through cache rule is associated with.</p>
    pub fn registry_id(&self) -> ::std::option::Option<&str> {
        self.registry_id.as_deref()
    }
    /// <p>The ARN of the Secrets Manager secret associated with the pull through cache rule.</p>
    pub fn credential_arn(&self) -> ::std::option::Option<&str> {
        self.credential_arn.as_deref()
    }
    /// <p>The ARN of the IAM role associated with the pull through cache rule.</p>
    pub fn custom_role_arn(&self) -> ::std::option::Option<&str> {
        self.custom_role_arn.as_deref()
    }
    /// <p>The upstream repository prefix associated with the pull through cache rule.</p>
    pub fn upstream_repository_prefix(&self) -> ::std::option::Option<&str> {
        self.upstream_repository_prefix.as_deref()
    }
    /// <p>The name of the upstream source registry associated with the pull through cache rule.</p>
    pub fn upstream_registry(&self) -> ::std::option::Option<&crate::types::UpstreamRegistry> {
        self.upstream_registry.as_ref()
    }
    /// <p>The date and time, in JavaScript date format, when the pull through cache rule was last updated.</p>
    pub fn updated_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.updated_at.as_ref()
    }
}
impl PullThroughCacheRule {
    /// Creates a new builder-style object to manufacture [`PullThroughCacheRule`](crate::types::PullThroughCacheRule).
    pub fn builder() -> crate::types::builders::PullThroughCacheRuleBuilder {
        crate::types::builders::PullThroughCacheRuleBuilder::default()
    }
}

/// A builder for [`PullThroughCacheRule`](crate::types::PullThroughCacheRule).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PullThroughCacheRuleBuilder {
    pub(crate) ecr_repository_prefix: ::std::option::Option<::std::string::String>,
    pub(crate) upstream_registry_url: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) registry_id: ::std::option::Option<::std::string::String>,
    pub(crate) credential_arn: ::std::option::Option<::std::string::String>,
    pub(crate) custom_role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) upstream_repository_prefix: ::std::option::Option<::std::string::String>,
    pub(crate) upstream_registry: ::std::option::Option<crate::types::UpstreamRegistry>,
    pub(crate) updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl PullThroughCacheRuleBuilder {
    /// <p>The Amazon ECR repository prefix associated with the pull through cache rule.</p>
    pub fn ecr_repository_prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ecr_repository_prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon ECR repository prefix associated with the pull through cache rule.</p>
    pub fn set_ecr_repository_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ecr_repository_prefix = input;
        self
    }
    /// <p>The Amazon ECR repository prefix associated with the pull through cache rule.</p>
    pub fn get_ecr_repository_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.ecr_repository_prefix
    }
    /// <p>The upstream registry URL associated with the pull through cache rule.</p>
    pub fn upstream_registry_url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.upstream_registry_url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The upstream registry URL associated with the pull through cache rule.</p>
    pub fn set_upstream_registry_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.upstream_registry_url = input;
        self
    }
    /// <p>The upstream registry URL associated with the pull through cache rule.</p>
    pub fn get_upstream_registry_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.upstream_registry_url
    }
    /// <p>The date and time the pull through cache was created.</p>
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time the pull through cache was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The date and time the pull through cache was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The Amazon Web Services account ID associated with the registry the pull through cache rule is associated with.</p>
    pub fn registry_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.registry_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID associated with the registry the pull through cache rule is associated with.</p>
    pub fn set_registry_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.registry_id = input;
        self
    }
    /// <p>The Amazon Web Services account ID associated with the registry the pull through cache rule is associated with.</p>
    pub fn get_registry_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.registry_id
    }
    /// <p>The ARN of the Secrets Manager secret associated with the pull through cache rule.</p>
    pub fn credential_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.credential_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the Secrets Manager secret associated with the pull through cache rule.</p>
    pub fn set_credential_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.credential_arn = input;
        self
    }
    /// <p>The ARN of the Secrets Manager secret associated with the pull through cache rule.</p>
    pub fn get_credential_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.credential_arn
    }
    /// <p>The ARN of the IAM role associated with the pull through cache rule.</p>
    pub fn custom_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.custom_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the IAM role associated with the pull through cache rule.</p>
    pub fn set_custom_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.custom_role_arn = input;
        self
    }
    /// <p>The ARN of the IAM role associated with the pull through cache rule.</p>
    pub fn get_custom_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.custom_role_arn
    }
    /// <p>The upstream repository prefix associated with the pull through cache rule.</p>
    pub fn upstream_repository_prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.upstream_repository_prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The upstream repository prefix associated with the pull through cache rule.</p>
    pub fn set_upstream_repository_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.upstream_repository_prefix = input;
        self
    }
    /// <p>The upstream repository prefix associated with the pull through cache rule.</p>
    pub fn get_upstream_repository_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.upstream_repository_prefix
    }
    /// <p>The name of the upstream source registry associated with the pull through cache rule.</p>
    pub fn upstream_registry(mut self, input: crate::types::UpstreamRegistry) -> Self {
        self.upstream_registry = ::std::option::Option::Some(input);
        self
    }
    /// <p>The name of the upstream source registry associated with the pull through cache rule.</p>
    pub fn set_upstream_registry(mut self, input: ::std::option::Option<crate::types::UpstreamRegistry>) -> Self {
        self.upstream_registry = input;
        self
    }
    /// <p>The name of the upstream source registry associated with the pull through cache rule.</p>
    pub fn get_upstream_registry(&self) -> &::std::option::Option<crate::types::UpstreamRegistry> {
        &self.upstream_registry
    }
    /// <p>The date and time, in JavaScript date format, when the pull through cache rule was last updated.</p>
    pub fn updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time, in JavaScript date format, when the pull through cache rule was last updated.</p>
    pub fn set_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.updated_at = input;
        self
    }
    /// <p>The date and time, in JavaScript date format, when the pull through cache rule was last updated.</p>
    pub fn get_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.updated_at
    }
    /// Consumes the builder and constructs a [`PullThroughCacheRule`](crate::types::PullThroughCacheRule).
    pub fn build(self) -> crate::types::PullThroughCacheRule {
        crate::types::PullThroughCacheRule {
            ecr_repository_prefix: self.ecr_repository_prefix,
            upstream_registry_url: self.upstream_registry_url,
            created_at: self.created_at,
            registry_id: self.registry_id,
            credential_arn: self.credential_arn,
            custom_role_arn: self.custom_role_arn,
            upstream_repository_prefix: self.upstream_repository_prefix,
            upstream_registry: self.upstream_registry,
            updated_at: self.updated_at,
        }
    }
}
