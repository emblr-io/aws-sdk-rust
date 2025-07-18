// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The infrastructure used when building Amazon EC2 AMIs.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InfrastructureConfigurationSummary {
    /// <p>The Amazon Resource Name (ARN) of the infrastructure configuration.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the infrastructure configuration.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The description of the infrastructure configuration.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The date on which the infrastructure configuration was created.</p>
    pub date_created: ::std::option::Option<::std::string::String>,
    /// <p>The date on which the infrastructure configuration was last updated.</p>
    pub date_updated: ::std::option::Option<::std::string::String>,
    /// <p>The tags attached to the image created by Image Builder.</p>
    pub resource_tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The tags of the infrastructure configuration.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The instance types of the infrastructure configuration.</p>
    pub instance_types: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The instance profile of the infrastructure configuration.</p>
    pub instance_profile_name: ::std::option::Option<::std::string::String>,
    /// <p>The instance placement settings that define where the instances that are launched from your image will run.</p>
    pub placement: ::std::option::Option<crate::types::Placement>,
}
impl InfrastructureConfigurationSummary {
    /// <p>The Amazon Resource Name (ARN) of the infrastructure configuration.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The name of the infrastructure configuration.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The description of the infrastructure configuration.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The date on which the infrastructure configuration was created.</p>
    pub fn date_created(&self) -> ::std::option::Option<&str> {
        self.date_created.as_deref()
    }
    /// <p>The date on which the infrastructure configuration was last updated.</p>
    pub fn date_updated(&self) -> ::std::option::Option<&str> {
        self.date_updated.as_deref()
    }
    /// <p>The tags attached to the image created by Image Builder.</p>
    pub fn resource_tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.resource_tags.as_ref()
    }
    /// <p>The tags of the infrastructure configuration.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>The instance types of the infrastructure configuration.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.instance_types.is_none()`.
    pub fn instance_types(&self) -> &[::std::string::String] {
        self.instance_types.as_deref().unwrap_or_default()
    }
    /// <p>The instance profile of the infrastructure configuration.</p>
    pub fn instance_profile_name(&self) -> ::std::option::Option<&str> {
        self.instance_profile_name.as_deref()
    }
    /// <p>The instance placement settings that define where the instances that are launched from your image will run.</p>
    pub fn placement(&self) -> ::std::option::Option<&crate::types::Placement> {
        self.placement.as_ref()
    }
}
impl InfrastructureConfigurationSummary {
    /// Creates a new builder-style object to manufacture [`InfrastructureConfigurationSummary`](crate::types::InfrastructureConfigurationSummary).
    pub fn builder() -> crate::types::builders::InfrastructureConfigurationSummaryBuilder {
        crate::types::builders::InfrastructureConfigurationSummaryBuilder::default()
    }
}

/// A builder for [`InfrastructureConfigurationSummary`](crate::types::InfrastructureConfigurationSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InfrastructureConfigurationSummaryBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) date_created: ::std::option::Option<::std::string::String>,
    pub(crate) date_updated: ::std::option::Option<::std::string::String>,
    pub(crate) resource_tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) instance_types: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) instance_profile_name: ::std::option::Option<::std::string::String>,
    pub(crate) placement: ::std::option::Option<crate::types::Placement>,
}
impl InfrastructureConfigurationSummaryBuilder {
    /// <p>The Amazon Resource Name (ARN) of the infrastructure configuration.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the infrastructure configuration.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the infrastructure configuration.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The name of the infrastructure configuration.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the infrastructure configuration.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the infrastructure configuration.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The description of the infrastructure configuration.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the infrastructure configuration.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the infrastructure configuration.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The date on which the infrastructure configuration was created.</p>
    pub fn date_created(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.date_created = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The date on which the infrastructure configuration was created.</p>
    pub fn set_date_created(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.date_created = input;
        self
    }
    /// <p>The date on which the infrastructure configuration was created.</p>
    pub fn get_date_created(&self) -> &::std::option::Option<::std::string::String> {
        &self.date_created
    }
    /// <p>The date on which the infrastructure configuration was last updated.</p>
    pub fn date_updated(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.date_updated = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The date on which the infrastructure configuration was last updated.</p>
    pub fn set_date_updated(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.date_updated = input;
        self
    }
    /// <p>The date on which the infrastructure configuration was last updated.</p>
    pub fn get_date_updated(&self) -> &::std::option::Option<::std::string::String> {
        &self.date_updated
    }
    /// Adds a key-value pair to `resource_tags`.
    ///
    /// To override the contents of this collection use [`set_resource_tags`](Self::set_resource_tags).
    ///
    /// <p>The tags attached to the image created by Image Builder.</p>
    pub fn resource_tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.resource_tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.resource_tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The tags attached to the image created by Image Builder.</p>
    pub fn set_resource_tags(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.resource_tags = input;
        self
    }
    /// <p>The tags attached to the image created by Image Builder.</p>
    pub fn get_resource_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.resource_tags
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags of the infrastructure configuration.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The tags of the infrastructure configuration.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags of the infrastructure configuration.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Appends an item to `instance_types`.
    ///
    /// To override the contents of this collection use [`set_instance_types`](Self::set_instance_types).
    ///
    /// <p>The instance types of the infrastructure configuration.</p>
    pub fn instance_types(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.instance_types.unwrap_or_default();
        v.push(input.into());
        self.instance_types = ::std::option::Option::Some(v);
        self
    }
    /// <p>The instance types of the infrastructure configuration.</p>
    pub fn set_instance_types(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.instance_types = input;
        self
    }
    /// <p>The instance types of the infrastructure configuration.</p>
    pub fn get_instance_types(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.instance_types
    }
    /// <p>The instance profile of the infrastructure configuration.</p>
    pub fn instance_profile_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_profile_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The instance profile of the infrastructure configuration.</p>
    pub fn set_instance_profile_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_profile_name = input;
        self
    }
    /// <p>The instance profile of the infrastructure configuration.</p>
    pub fn get_instance_profile_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_profile_name
    }
    /// <p>The instance placement settings that define where the instances that are launched from your image will run.</p>
    pub fn placement(mut self, input: crate::types::Placement) -> Self {
        self.placement = ::std::option::Option::Some(input);
        self
    }
    /// <p>The instance placement settings that define where the instances that are launched from your image will run.</p>
    pub fn set_placement(mut self, input: ::std::option::Option<crate::types::Placement>) -> Self {
        self.placement = input;
        self
    }
    /// <p>The instance placement settings that define where the instances that are launched from your image will run.</p>
    pub fn get_placement(&self) -> &::std::option::Option<crate::types::Placement> {
        &self.placement
    }
    /// Consumes the builder and constructs a [`InfrastructureConfigurationSummary`](crate::types::InfrastructureConfigurationSummary).
    pub fn build(self) -> crate::types::InfrastructureConfigurationSummary {
        crate::types::InfrastructureConfigurationSummary {
            arn: self.arn,
            name: self.name,
            description: self.description,
            date_created: self.date_created,
            date_updated: self.date_updated,
            resource_tags: self.resource_tags,
            tags: self.tags,
            instance_types: self.instance_types,
            instance_profile_name: self.instance_profile_name,
            placement: self.placement,
        }
    }
}
