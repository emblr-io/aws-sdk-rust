// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains a summary of lifecycle policy resources.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LifecyclePolicySummary {
    /// <p>The Amazon Resource Name (ARN) of the lifecycle policy summary resource.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the lifecycle policy.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>Optional description for the lifecycle policy.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The lifecycle policy resource status.</p>
    pub status: ::std::option::Option<crate::types::LifecyclePolicyStatus>,
    /// <p>The name or Amazon Resource Name (ARN) of the IAM role that Image Builder uses to run the lifecycle policy.</p>
    pub execution_role: ::std::option::Option<::std::string::String>,
    /// <p>The type of resources the lifecycle policy targets.</p>
    pub resource_type: ::std::option::Option<crate::types::LifecyclePolicyResourceType>,
    /// <p>The timestamp when Image Builder created the lifecycle policy resource.</p>
    pub date_created: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The timestamp when Image Builder updated the lifecycle policy resource.</p>
    pub date_updated: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The timestamp for the last time Image Builder ran the lifecycle policy.</p>
    pub date_last_run: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>To help manage your lifecycle policy resources, you can assign your own metadata to each resource in the form of tags. Each tag consists of a key and an optional value, both of which you define.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl LifecyclePolicySummary {
    /// <p>The Amazon Resource Name (ARN) of the lifecycle policy summary resource.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The name of the lifecycle policy.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>Optional description for the lifecycle policy.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The lifecycle policy resource status.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::LifecyclePolicyStatus> {
        self.status.as_ref()
    }
    /// <p>The name or Amazon Resource Name (ARN) of the IAM role that Image Builder uses to run the lifecycle policy.</p>
    pub fn execution_role(&self) -> ::std::option::Option<&str> {
        self.execution_role.as_deref()
    }
    /// <p>The type of resources the lifecycle policy targets.</p>
    pub fn resource_type(&self) -> ::std::option::Option<&crate::types::LifecyclePolicyResourceType> {
        self.resource_type.as_ref()
    }
    /// <p>The timestamp when Image Builder created the lifecycle policy resource.</p>
    pub fn date_created(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.date_created.as_ref()
    }
    /// <p>The timestamp when Image Builder updated the lifecycle policy resource.</p>
    pub fn date_updated(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.date_updated.as_ref()
    }
    /// <p>The timestamp for the last time Image Builder ran the lifecycle policy.</p>
    pub fn date_last_run(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.date_last_run.as_ref()
    }
    /// <p>To help manage your lifecycle policy resources, you can assign your own metadata to each resource in the form of tags. Each tag consists of a key and an optional value, both of which you define.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl LifecyclePolicySummary {
    /// Creates a new builder-style object to manufacture [`LifecyclePolicySummary`](crate::types::LifecyclePolicySummary).
    pub fn builder() -> crate::types::builders::LifecyclePolicySummaryBuilder {
        crate::types::builders::LifecyclePolicySummaryBuilder::default()
    }
}

/// A builder for [`LifecyclePolicySummary`](crate::types::LifecyclePolicySummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LifecyclePolicySummaryBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::LifecyclePolicyStatus>,
    pub(crate) execution_role: ::std::option::Option<::std::string::String>,
    pub(crate) resource_type: ::std::option::Option<crate::types::LifecyclePolicyResourceType>,
    pub(crate) date_created: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) date_updated: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) date_last_run: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl LifecyclePolicySummaryBuilder {
    /// <p>The Amazon Resource Name (ARN) of the lifecycle policy summary resource.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the lifecycle policy summary resource.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the lifecycle policy summary resource.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The name of the lifecycle policy.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the lifecycle policy.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the lifecycle policy.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>Optional description for the lifecycle policy.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Optional description for the lifecycle policy.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>Optional description for the lifecycle policy.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The lifecycle policy resource status.</p>
    pub fn status(mut self, input: crate::types::LifecyclePolicyStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The lifecycle policy resource status.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::LifecyclePolicyStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The lifecycle policy resource status.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::LifecyclePolicyStatus> {
        &self.status
    }
    /// <p>The name or Amazon Resource Name (ARN) of the IAM role that Image Builder uses to run the lifecycle policy.</p>
    pub fn execution_role(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.execution_role = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name or Amazon Resource Name (ARN) of the IAM role that Image Builder uses to run the lifecycle policy.</p>
    pub fn set_execution_role(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.execution_role = input;
        self
    }
    /// <p>The name or Amazon Resource Name (ARN) of the IAM role that Image Builder uses to run the lifecycle policy.</p>
    pub fn get_execution_role(&self) -> &::std::option::Option<::std::string::String> {
        &self.execution_role
    }
    /// <p>The type of resources the lifecycle policy targets.</p>
    pub fn resource_type(mut self, input: crate::types::LifecyclePolicyResourceType) -> Self {
        self.resource_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of resources the lifecycle policy targets.</p>
    pub fn set_resource_type(mut self, input: ::std::option::Option<crate::types::LifecyclePolicyResourceType>) -> Self {
        self.resource_type = input;
        self
    }
    /// <p>The type of resources the lifecycle policy targets.</p>
    pub fn get_resource_type(&self) -> &::std::option::Option<crate::types::LifecyclePolicyResourceType> {
        &self.resource_type
    }
    /// <p>The timestamp when Image Builder created the lifecycle policy resource.</p>
    pub fn date_created(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.date_created = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp when Image Builder created the lifecycle policy resource.</p>
    pub fn set_date_created(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.date_created = input;
        self
    }
    /// <p>The timestamp when Image Builder created the lifecycle policy resource.</p>
    pub fn get_date_created(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.date_created
    }
    /// <p>The timestamp when Image Builder updated the lifecycle policy resource.</p>
    pub fn date_updated(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.date_updated = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp when Image Builder updated the lifecycle policy resource.</p>
    pub fn set_date_updated(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.date_updated = input;
        self
    }
    /// <p>The timestamp when Image Builder updated the lifecycle policy resource.</p>
    pub fn get_date_updated(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.date_updated
    }
    /// <p>The timestamp for the last time Image Builder ran the lifecycle policy.</p>
    pub fn date_last_run(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.date_last_run = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp for the last time Image Builder ran the lifecycle policy.</p>
    pub fn set_date_last_run(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.date_last_run = input;
        self
    }
    /// <p>The timestamp for the last time Image Builder ran the lifecycle policy.</p>
    pub fn get_date_last_run(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.date_last_run
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>To help manage your lifecycle policy resources, you can assign your own metadata to each resource in the form of tags. Each tag consists of a key and an optional value, both of which you define.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>To help manage your lifecycle policy resources, you can assign your own metadata to each resource in the form of tags. Each tag consists of a key and an optional value, both of which you define.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>To help manage your lifecycle policy resources, you can assign your own metadata to each resource in the form of tags. Each tag consists of a key and an optional value, both of which you define.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`LifecyclePolicySummary`](crate::types::LifecyclePolicySummary).
    pub fn build(self) -> crate::types::LifecyclePolicySummary {
        crate::types::LifecyclePolicySummary {
            arn: self.arn,
            name: self.name,
            description: self.description,
            status: self.status,
            execution_role: self.execution_role,
            resource_type: self.resource_type,
            date_created: self.date_created,
            date_updated: self.date_updated,
            date_last_run: self.date_last_run,
            tags: self.tags,
        }
    }
}
