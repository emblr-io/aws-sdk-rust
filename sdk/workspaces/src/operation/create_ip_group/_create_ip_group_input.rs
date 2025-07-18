// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateIpGroupInput {
    /// <p>The name of the group.</p>
    pub group_name: ::std::option::Option<::std::string::String>,
    /// <p>The description of the group.</p>
    pub group_desc: ::std::option::Option<::std::string::String>,
    /// <p>The rules to add to the group.</p>
    pub user_rules: ::std::option::Option<::std::vec::Vec<crate::types::IpRuleItem>>,
    /// <p>The tags. Each WorkSpaces resource can have a maximum of 50 tags.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateIpGroupInput {
    /// <p>The name of the group.</p>
    pub fn group_name(&self) -> ::std::option::Option<&str> {
        self.group_name.as_deref()
    }
    /// <p>The description of the group.</p>
    pub fn group_desc(&self) -> ::std::option::Option<&str> {
        self.group_desc.as_deref()
    }
    /// <p>The rules to add to the group.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.user_rules.is_none()`.
    pub fn user_rules(&self) -> &[crate::types::IpRuleItem] {
        self.user_rules.as_deref().unwrap_or_default()
    }
    /// <p>The tags. Each WorkSpaces resource can have a maximum of 50 tags.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl CreateIpGroupInput {
    /// Creates a new builder-style object to manufacture [`CreateIpGroupInput`](crate::operation::create_ip_group::CreateIpGroupInput).
    pub fn builder() -> crate::operation::create_ip_group::builders::CreateIpGroupInputBuilder {
        crate::operation::create_ip_group::builders::CreateIpGroupInputBuilder::default()
    }
}

/// A builder for [`CreateIpGroupInput`](crate::operation::create_ip_group::CreateIpGroupInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateIpGroupInputBuilder {
    pub(crate) group_name: ::std::option::Option<::std::string::String>,
    pub(crate) group_desc: ::std::option::Option<::std::string::String>,
    pub(crate) user_rules: ::std::option::Option<::std::vec::Vec<crate::types::IpRuleItem>>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateIpGroupInputBuilder {
    /// <p>The name of the group.</p>
    /// This field is required.
    pub fn group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the group.</p>
    pub fn set_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.group_name = input;
        self
    }
    /// <p>The name of the group.</p>
    pub fn get_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.group_name
    }
    /// <p>The description of the group.</p>
    pub fn group_desc(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.group_desc = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the group.</p>
    pub fn set_group_desc(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.group_desc = input;
        self
    }
    /// <p>The description of the group.</p>
    pub fn get_group_desc(&self) -> &::std::option::Option<::std::string::String> {
        &self.group_desc
    }
    /// Appends an item to `user_rules`.
    ///
    /// To override the contents of this collection use [`set_user_rules`](Self::set_user_rules).
    ///
    /// <p>The rules to add to the group.</p>
    pub fn user_rules(mut self, input: crate::types::IpRuleItem) -> Self {
        let mut v = self.user_rules.unwrap_or_default();
        v.push(input);
        self.user_rules = ::std::option::Option::Some(v);
        self
    }
    /// <p>The rules to add to the group.</p>
    pub fn set_user_rules(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::IpRuleItem>>) -> Self {
        self.user_rules = input;
        self
    }
    /// <p>The rules to add to the group.</p>
    pub fn get_user_rules(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::IpRuleItem>> {
        &self.user_rules
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags. Each WorkSpaces resource can have a maximum of 50 tags.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The tags. Each WorkSpaces resource can have a maximum of 50 tags.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags. Each WorkSpaces resource can have a maximum of 50 tags.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateIpGroupInput`](crate::operation::create_ip_group::CreateIpGroupInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_ip_group::CreateIpGroupInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_ip_group::CreateIpGroupInput {
            group_name: self.group_name,
            group_desc: self.group_desc,
            user_rules: self.user_rules,
            tags: self.tags,
        })
    }
}
