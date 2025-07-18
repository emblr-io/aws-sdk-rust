// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a link.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Link {
    /// <p>The ID of the link.</p>
    pub link_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the link.</p>
    pub link_arn: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the global network.</p>
    pub global_network_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the site.</p>
    pub site_id: ::std::option::Option<::std::string::String>,
    /// <p>The description of the link.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The type of the link.</p>
    pub r#type: ::std::option::Option<::std::string::String>,
    /// <p>The bandwidth for the link.</p>
    pub bandwidth: ::std::option::Option<crate::types::Bandwidth>,
    /// <p>The provider of the link.</p>
    pub provider: ::std::option::Option<::std::string::String>,
    /// <p>The date and time that the link was created.</p>
    pub created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The state of the link.</p>
    pub state: ::std::option::Option<crate::types::LinkState>,
    /// <p>The tags for the link.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl Link {
    /// <p>The ID of the link.</p>
    pub fn link_id(&self) -> ::std::option::Option<&str> {
        self.link_id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the link.</p>
    pub fn link_arn(&self) -> ::std::option::Option<&str> {
        self.link_arn.as_deref()
    }
    /// <p>The ID of the global network.</p>
    pub fn global_network_id(&self) -> ::std::option::Option<&str> {
        self.global_network_id.as_deref()
    }
    /// <p>The ID of the site.</p>
    pub fn site_id(&self) -> ::std::option::Option<&str> {
        self.site_id.as_deref()
    }
    /// <p>The description of the link.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The type of the link.</p>
    pub fn r#type(&self) -> ::std::option::Option<&str> {
        self.r#type.as_deref()
    }
    /// <p>The bandwidth for the link.</p>
    pub fn bandwidth(&self) -> ::std::option::Option<&crate::types::Bandwidth> {
        self.bandwidth.as_ref()
    }
    /// <p>The provider of the link.</p>
    pub fn provider(&self) -> ::std::option::Option<&str> {
        self.provider.as_deref()
    }
    /// <p>The date and time that the link was created.</p>
    pub fn created_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_at.as_ref()
    }
    /// <p>The state of the link.</p>
    pub fn state(&self) -> ::std::option::Option<&crate::types::LinkState> {
        self.state.as_ref()
    }
    /// <p>The tags for the link.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl Link {
    /// Creates a new builder-style object to manufacture [`Link`](crate::types::Link).
    pub fn builder() -> crate::types::builders::LinkBuilder {
        crate::types::builders::LinkBuilder::default()
    }
}

/// A builder for [`Link`](crate::types::Link).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LinkBuilder {
    pub(crate) link_id: ::std::option::Option<::std::string::String>,
    pub(crate) link_arn: ::std::option::Option<::std::string::String>,
    pub(crate) global_network_id: ::std::option::Option<::std::string::String>,
    pub(crate) site_id: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<::std::string::String>,
    pub(crate) bandwidth: ::std::option::Option<crate::types::Bandwidth>,
    pub(crate) provider: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) state: ::std::option::Option<crate::types::LinkState>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl LinkBuilder {
    /// <p>The ID of the link.</p>
    pub fn link_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.link_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the link.</p>
    pub fn set_link_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.link_id = input;
        self
    }
    /// <p>The ID of the link.</p>
    pub fn get_link_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.link_id
    }
    /// <p>The Amazon Resource Name (ARN) of the link.</p>
    pub fn link_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.link_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the link.</p>
    pub fn set_link_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.link_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the link.</p>
    pub fn get_link_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.link_arn
    }
    /// <p>The ID of the global network.</p>
    pub fn global_network_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.global_network_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the global network.</p>
    pub fn set_global_network_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.global_network_id = input;
        self
    }
    /// <p>The ID of the global network.</p>
    pub fn get_global_network_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.global_network_id
    }
    /// <p>The ID of the site.</p>
    pub fn site_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.site_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the site.</p>
    pub fn set_site_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.site_id = input;
        self
    }
    /// <p>The ID of the site.</p>
    pub fn get_site_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.site_id
    }
    /// <p>The description of the link.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the link.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the link.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The type of the link.</p>
    pub fn r#type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.r#type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of the link.</p>
    pub fn set_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of the link.</p>
    pub fn get_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.r#type
    }
    /// <p>The bandwidth for the link.</p>
    pub fn bandwidth(mut self, input: crate::types::Bandwidth) -> Self {
        self.bandwidth = ::std::option::Option::Some(input);
        self
    }
    /// <p>The bandwidth for the link.</p>
    pub fn set_bandwidth(mut self, input: ::std::option::Option<crate::types::Bandwidth>) -> Self {
        self.bandwidth = input;
        self
    }
    /// <p>The bandwidth for the link.</p>
    pub fn get_bandwidth(&self) -> &::std::option::Option<crate::types::Bandwidth> {
        &self.bandwidth
    }
    /// <p>The provider of the link.</p>
    pub fn provider(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.provider = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The provider of the link.</p>
    pub fn set_provider(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.provider = input;
        self
    }
    /// <p>The provider of the link.</p>
    pub fn get_provider(&self) -> &::std::option::Option<::std::string::String> {
        &self.provider
    }
    /// <p>The date and time that the link was created.</p>
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time that the link was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The date and time that the link was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The state of the link.</p>
    pub fn state(mut self, input: crate::types::LinkState) -> Self {
        self.state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The state of the link.</p>
    pub fn set_state(mut self, input: ::std::option::Option<crate::types::LinkState>) -> Self {
        self.state = input;
        self
    }
    /// <p>The state of the link.</p>
    pub fn get_state(&self) -> &::std::option::Option<crate::types::LinkState> {
        &self.state
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags for the link.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The tags for the link.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags for the link.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`Link`](crate::types::Link).
    pub fn build(self) -> crate::types::Link {
        crate::types::Link {
            link_id: self.link_id,
            link_arn: self.link_arn,
            global_network_id: self.global_network_id,
            site_id: self.site_id,
            description: self.description,
            r#type: self.r#type,
            bandwidth: self.bandwidth,
            provider: self.provider,
            created_at: self.created_at,
            state: self.state,
            tags: self.tags,
        }
    }
}
