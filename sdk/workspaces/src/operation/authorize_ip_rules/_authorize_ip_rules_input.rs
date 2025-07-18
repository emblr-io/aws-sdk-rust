// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AuthorizeIpRulesInput {
    /// <p>The identifier of the group.</p>
    pub group_id: ::std::option::Option<::std::string::String>,
    /// <p>The rules to add to the group.</p>
    pub user_rules: ::std::option::Option<::std::vec::Vec<crate::types::IpRuleItem>>,
}
impl AuthorizeIpRulesInput {
    /// <p>The identifier of the group.</p>
    pub fn group_id(&self) -> ::std::option::Option<&str> {
        self.group_id.as_deref()
    }
    /// <p>The rules to add to the group.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.user_rules.is_none()`.
    pub fn user_rules(&self) -> &[crate::types::IpRuleItem] {
        self.user_rules.as_deref().unwrap_or_default()
    }
}
impl AuthorizeIpRulesInput {
    /// Creates a new builder-style object to manufacture [`AuthorizeIpRulesInput`](crate::operation::authorize_ip_rules::AuthorizeIpRulesInput).
    pub fn builder() -> crate::operation::authorize_ip_rules::builders::AuthorizeIpRulesInputBuilder {
        crate::operation::authorize_ip_rules::builders::AuthorizeIpRulesInputBuilder::default()
    }
}

/// A builder for [`AuthorizeIpRulesInput`](crate::operation::authorize_ip_rules::AuthorizeIpRulesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AuthorizeIpRulesInputBuilder {
    pub(crate) group_id: ::std::option::Option<::std::string::String>,
    pub(crate) user_rules: ::std::option::Option<::std::vec::Vec<crate::types::IpRuleItem>>,
}
impl AuthorizeIpRulesInputBuilder {
    /// <p>The identifier of the group.</p>
    /// This field is required.
    pub fn group_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.group_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the group.</p>
    pub fn set_group_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.group_id = input;
        self
    }
    /// <p>The identifier of the group.</p>
    pub fn get_group_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.group_id
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
    /// Consumes the builder and constructs a [`AuthorizeIpRulesInput`](crate::operation::authorize_ip_rules::AuthorizeIpRulesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::authorize_ip_rules::AuthorizeIpRulesInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::authorize_ip_rules::AuthorizeIpRulesInput {
            group_id: self.group_id,
            user_rules: self.user_rules,
        })
    }
}
