// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Summary information about a resource configuration.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ResourceConfigurationSummary {
    /// <p>The ID of the resource configuration.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the resource configuration.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the resource configuration.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the resource gateway.</p>
    pub resource_gateway_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the group resource configuration.</p>
    pub resource_configuration_group_id: ::std::option::Option<::std::string::String>,
    /// <p>The type of resource configuration.</p>
    /// <ul>
    /// <li>
    /// <p><code>SINGLE</code> - A single resource.</p></li>
    /// <li>
    /// <p><code>GROUP</code> - A group of resources.</p></li>
    /// <li>
    /// <p><code>CHILD</code> - A single resource that is part of a group resource configuration.</p></li>
    /// <li>
    /// <p><code>ARN</code> - An Amazon Web Services resource.</p></li>
    /// </ul>
    pub r#type: ::std::option::Option<crate::types::ResourceConfigurationType>,
    /// <p>The status of the resource configuration.</p>
    pub status: ::std::option::Option<crate::types::ResourceConfigurationStatus>,
    /// <p>Indicates whether the resource configuration was created and is managed by Amazon.</p>
    pub amazon_managed: ::std::option::Option<bool>,
    /// <p>The date and time that the resource configuration was created, in ISO-8601 format.</p>
    pub created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The most recent date and time that the resource configuration was updated, in ISO-8601 format.</p>
    pub last_updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ResourceConfigurationSummary {
    /// <p>The ID of the resource configuration.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The name of the resource configuration.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the resource configuration.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The ID of the resource gateway.</p>
    pub fn resource_gateway_id(&self) -> ::std::option::Option<&str> {
        self.resource_gateway_id.as_deref()
    }
    /// <p>The ID of the group resource configuration.</p>
    pub fn resource_configuration_group_id(&self) -> ::std::option::Option<&str> {
        self.resource_configuration_group_id.as_deref()
    }
    /// <p>The type of resource configuration.</p>
    /// <ul>
    /// <li>
    /// <p><code>SINGLE</code> - A single resource.</p></li>
    /// <li>
    /// <p><code>GROUP</code> - A group of resources.</p></li>
    /// <li>
    /// <p><code>CHILD</code> - A single resource that is part of a group resource configuration.</p></li>
    /// <li>
    /// <p><code>ARN</code> - An Amazon Web Services resource.</p></li>
    /// </ul>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::ResourceConfigurationType> {
        self.r#type.as_ref()
    }
    /// <p>The status of the resource configuration.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::ResourceConfigurationStatus> {
        self.status.as_ref()
    }
    /// <p>Indicates whether the resource configuration was created and is managed by Amazon.</p>
    pub fn amazon_managed(&self) -> ::std::option::Option<bool> {
        self.amazon_managed
    }
    /// <p>The date and time that the resource configuration was created, in ISO-8601 format.</p>
    pub fn created_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_at.as_ref()
    }
    /// <p>The most recent date and time that the resource configuration was updated, in ISO-8601 format.</p>
    pub fn last_updated_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_updated_at.as_ref()
    }
}
impl ResourceConfigurationSummary {
    /// Creates a new builder-style object to manufacture [`ResourceConfigurationSummary`](crate::types::ResourceConfigurationSummary).
    pub fn builder() -> crate::types::builders::ResourceConfigurationSummaryBuilder {
        crate::types::builders::ResourceConfigurationSummaryBuilder::default()
    }
}

/// A builder for [`ResourceConfigurationSummary`](crate::types::ResourceConfigurationSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ResourceConfigurationSummaryBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) resource_gateway_id: ::std::option::Option<::std::string::String>,
    pub(crate) resource_configuration_group_id: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::ResourceConfigurationType>,
    pub(crate) status: ::std::option::Option<crate::types::ResourceConfigurationStatus>,
    pub(crate) amazon_managed: ::std::option::Option<bool>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ResourceConfigurationSummaryBuilder {
    /// <p>The ID of the resource configuration.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the resource configuration.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID of the resource configuration.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The name of the resource configuration.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the resource configuration.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the resource configuration.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The Amazon Resource Name (ARN) of the resource configuration.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the resource configuration.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the resource configuration.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The ID of the resource gateway.</p>
    pub fn resource_gateway_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_gateway_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the resource gateway.</p>
    pub fn set_resource_gateway_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_gateway_id = input;
        self
    }
    /// <p>The ID of the resource gateway.</p>
    pub fn get_resource_gateway_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_gateway_id
    }
    /// <p>The ID of the group resource configuration.</p>
    pub fn resource_configuration_group_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_configuration_group_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the group resource configuration.</p>
    pub fn set_resource_configuration_group_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_configuration_group_id = input;
        self
    }
    /// <p>The ID of the group resource configuration.</p>
    pub fn get_resource_configuration_group_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_configuration_group_id
    }
    /// <p>The type of resource configuration.</p>
    /// <ul>
    /// <li>
    /// <p><code>SINGLE</code> - A single resource.</p></li>
    /// <li>
    /// <p><code>GROUP</code> - A group of resources.</p></li>
    /// <li>
    /// <p><code>CHILD</code> - A single resource that is part of a group resource configuration.</p></li>
    /// <li>
    /// <p><code>ARN</code> - An Amazon Web Services resource.</p></li>
    /// </ul>
    pub fn r#type(mut self, input: crate::types::ResourceConfigurationType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of resource configuration.</p>
    /// <ul>
    /// <li>
    /// <p><code>SINGLE</code> - A single resource.</p></li>
    /// <li>
    /// <p><code>GROUP</code> - A group of resources.</p></li>
    /// <li>
    /// <p><code>CHILD</code> - A single resource that is part of a group resource configuration.</p></li>
    /// <li>
    /// <p><code>ARN</code> - An Amazon Web Services resource.</p></li>
    /// </ul>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::ResourceConfigurationType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of resource configuration.</p>
    /// <ul>
    /// <li>
    /// <p><code>SINGLE</code> - A single resource.</p></li>
    /// <li>
    /// <p><code>GROUP</code> - A group of resources.</p></li>
    /// <li>
    /// <p><code>CHILD</code> - A single resource that is part of a group resource configuration.</p></li>
    /// <li>
    /// <p><code>ARN</code> - An Amazon Web Services resource.</p></li>
    /// </ul>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::ResourceConfigurationType> {
        &self.r#type
    }
    /// <p>The status of the resource configuration.</p>
    pub fn status(mut self, input: crate::types::ResourceConfigurationStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the resource configuration.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::ResourceConfigurationStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the resource configuration.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::ResourceConfigurationStatus> {
        &self.status
    }
    /// <p>Indicates whether the resource configuration was created and is managed by Amazon.</p>
    pub fn amazon_managed(mut self, input: bool) -> Self {
        self.amazon_managed = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the resource configuration was created and is managed by Amazon.</p>
    pub fn set_amazon_managed(mut self, input: ::std::option::Option<bool>) -> Self {
        self.amazon_managed = input;
        self
    }
    /// <p>Indicates whether the resource configuration was created and is managed by Amazon.</p>
    pub fn get_amazon_managed(&self) -> &::std::option::Option<bool> {
        &self.amazon_managed
    }
    /// <p>The date and time that the resource configuration was created, in ISO-8601 format.</p>
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time that the resource configuration was created, in ISO-8601 format.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The date and time that the resource configuration was created, in ISO-8601 format.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The most recent date and time that the resource configuration was updated, in ISO-8601 format.</p>
    pub fn last_updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The most recent date and time that the resource configuration was updated, in ISO-8601 format.</p>
    pub fn set_last_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated_at = input;
        self
    }
    /// <p>The most recent date and time that the resource configuration was updated, in ISO-8601 format.</p>
    pub fn get_last_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated_at
    }
    /// Consumes the builder and constructs a [`ResourceConfigurationSummary`](crate::types::ResourceConfigurationSummary).
    pub fn build(self) -> crate::types::ResourceConfigurationSummary {
        crate::types::ResourceConfigurationSummary {
            id: self.id,
            name: self.name,
            arn: self.arn,
            resource_gateway_id: self.resource_gateway_id,
            resource_configuration_group_id: self.resource_configuration_group_id,
            r#type: self.r#type,
            status: self.status,
            amazon_managed: self.amazon_managed,
            created_at: self.created_at,
            last_updated_at: self.last_updated_at,
        }
    }
}
