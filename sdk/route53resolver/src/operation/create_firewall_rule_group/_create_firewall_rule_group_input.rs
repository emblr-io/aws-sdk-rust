// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateFirewallRuleGroupInput {
    /// <p>A unique string defined by you to identify the request. This allows you to retry failed requests without the risk of running the operation twice. This can be any unique string, for example, a timestamp.</p>
    pub creator_request_id: ::std::option::Option<::std::string::String>,
    /// <p>A name that lets you identify the rule group, to manage and use it.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>A list of the tag keys and values that you want to associate with the rule group.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateFirewallRuleGroupInput {
    /// <p>A unique string defined by you to identify the request. This allows you to retry failed requests without the risk of running the operation twice. This can be any unique string, for example, a timestamp.</p>
    pub fn creator_request_id(&self) -> ::std::option::Option<&str> {
        self.creator_request_id.as_deref()
    }
    /// <p>A name that lets you identify the rule group, to manage and use it.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>A list of the tag keys and values that you want to associate with the rule group.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl CreateFirewallRuleGroupInput {
    /// Creates a new builder-style object to manufacture [`CreateFirewallRuleGroupInput`](crate::operation::create_firewall_rule_group::CreateFirewallRuleGroupInput).
    pub fn builder() -> crate::operation::create_firewall_rule_group::builders::CreateFirewallRuleGroupInputBuilder {
        crate::operation::create_firewall_rule_group::builders::CreateFirewallRuleGroupInputBuilder::default()
    }
}

/// A builder for [`CreateFirewallRuleGroupInput`](crate::operation::create_firewall_rule_group::CreateFirewallRuleGroupInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateFirewallRuleGroupInputBuilder {
    pub(crate) creator_request_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateFirewallRuleGroupInputBuilder {
    /// <p>A unique string defined by you to identify the request. This allows you to retry failed requests without the risk of running the operation twice. This can be any unique string, for example, a timestamp.</p>
    /// This field is required.
    pub fn creator_request_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.creator_request_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique string defined by you to identify the request. This allows you to retry failed requests without the risk of running the operation twice. This can be any unique string, for example, a timestamp.</p>
    pub fn set_creator_request_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.creator_request_id = input;
        self
    }
    /// <p>A unique string defined by you to identify the request. This allows you to retry failed requests without the risk of running the operation twice. This can be any unique string, for example, a timestamp.</p>
    pub fn get_creator_request_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.creator_request_id
    }
    /// <p>A name that lets you identify the rule group, to manage and use it.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A name that lets you identify the rule group, to manage and use it.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>A name that lets you identify the rule group, to manage and use it.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A list of the tag keys and values that you want to associate with the rule group.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of the tag keys and values that you want to associate with the rule group.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A list of the tag keys and values that you want to associate with the rule group.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateFirewallRuleGroupInput`](crate::operation::create_firewall_rule_group::CreateFirewallRuleGroupInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_firewall_rule_group::CreateFirewallRuleGroupInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_firewall_rule_group::CreateFirewallRuleGroupInput {
            creator_request_id: self.creator_request_id,
            name: self.name,
            tags: self.tags,
        })
    }
}
