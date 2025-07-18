// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateWebAclInput {
    /// <p>The <code>WebACLId</code> of the <code>WebACL</code> that you want to update. <code>WebACLId</code> is returned by <code>CreateWebACL</code> and by <code>ListWebACLs</code>.</p>
    pub web_acl_id: ::std::option::Option<::std::string::String>,
    /// <p>The value returned by the most recent call to <code>GetChangeToken</code>.</p>
    pub change_token: ::std::option::Option<::std::string::String>,
    /// <p>An array of updates to make to the <code>WebACL</code>.</p>
    /// <p>An array of <code>WebACLUpdate</code> objects that you want to insert into or delete from a <code>WebACL</code>. For more information, see the applicable data types:</p>
    /// <ul>
    /// <li>
    /// <p><code>WebACLUpdate</code>: Contains <code>Action</code> and <code>ActivatedRule</code></p></li>
    /// <li>
    /// <p><code>ActivatedRule</code>: Contains <code>Action</code>, <code>OverrideAction</code>, <code>Priority</code>, <code>RuleId</code>, and <code>Type</code>. <code>ActivatedRule|OverrideAction</code> applies only when updating or adding a <code>RuleGroup</code> to a <code>WebACL</code>. In this case, you do not use <code>ActivatedRule|Action</code>. For all other update requests, <code>ActivatedRule|Action</code> is used instead of <code>ActivatedRule|OverrideAction</code>.</p></li>
    /// <li>
    /// <p><code>WafAction</code>: Contains <code>Type</code></p></li>
    /// </ul>
    pub updates: ::std::option::Option<::std::vec::Vec<crate::types::WebAclUpdate>>,
    /// <p>A default action for the web ACL, either ALLOW or BLOCK. AWS WAF performs the default action if a request doesn't match the criteria in any of the rules in a web ACL.</p>
    pub default_action: ::std::option::Option<crate::types::WafAction>,
}
impl UpdateWebAclInput {
    /// <p>The <code>WebACLId</code> of the <code>WebACL</code> that you want to update. <code>WebACLId</code> is returned by <code>CreateWebACL</code> and by <code>ListWebACLs</code>.</p>
    pub fn web_acl_id(&self) -> ::std::option::Option<&str> {
        self.web_acl_id.as_deref()
    }
    /// <p>The value returned by the most recent call to <code>GetChangeToken</code>.</p>
    pub fn change_token(&self) -> ::std::option::Option<&str> {
        self.change_token.as_deref()
    }
    /// <p>An array of updates to make to the <code>WebACL</code>.</p>
    /// <p>An array of <code>WebACLUpdate</code> objects that you want to insert into or delete from a <code>WebACL</code>. For more information, see the applicable data types:</p>
    /// <ul>
    /// <li>
    /// <p><code>WebACLUpdate</code>: Contains <code>Action</code> and <code>ActivatedRule</code></p></li>
    /// <li>
    /// <p><code>ActivatedRule</code>: Contains <code>Action</code>, <code>OverrideAction</code>, <code>Priority</code>, <code>RuleId</code>, and <code>Type</code>. <code>ActivatedRule|OverrideAction</code> applies only when updating or adding a <code>RuleGroup</code> to a <code>WebACL</code>. In this case, you do not use <code>ActivatedRule|Action</code>. For all other update requests, <code>ActivatedRule|Action</code> is used instead of <code>ActivatedRule|OverrideAction</code>.</p></li>
    /// <li>
    /// <p><code>WafAction</code>: Contains <code>Type</code></p></li>
    /// </ul>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.updates.is_none()`.
    pub fn updates(&self) -> &[crate::types::WebAclUpdate] {
        self.updates.as_deref().unwrap_or_default()
    }
    /// <p>A default action for the web ACL, either ALLOW or BLOCK. AWS WAF performs the default action if a request doesn't match the criteria in any of the rules in a web ACL.</p>
    pub fn default_action(&self) -> ::std::option::Option<&crate::types::WafAction> {
        self.default_action.as_ref()
    }
}
impl UpdateWebAclInput {
    /// Creates a new builder-style object to manufacture [`UpdateWebAclInput`](crate::operation::update_web_acl::UpdateWebAclInput).
    pub fn builder() -> crate::operation::update_web_acl::builders::UpdateWebAclInputBuilder {
        crate::operation::update_web_acl::builders::UpdateWebAclInputBuilder::default()
    }
}

/// A builder for [`UpdateWebAclInput`](crate::operation::update_web_acl::UpdateWebAclInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateWebAclInputBuilder {
    pub(crate) web_acl_id: ::std::option::Option<::std::string::String>,
    pub(crate) change_token: ::std::option::Option<::std::string::String>,
    pub(crate) updates: ::std::option::Option<::std::vec::Vec<crate::types::WebAclUpdate>>,
    pub(crate) default_action: ::std::option::Option<crate::types::WafAction>,
}
impl UpdateWebAclInputBuilder {
    /// <p>The <code>WebACLId</code> of the <code>WebACL</code> that you want to update. <code>WebACLId</code> is returned by <code>CreateWebACL</code> and by <code>ListWebACLs</code>.</p>
    /// This field is required.
    pub fn web_acl_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.web_acl_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>WebACLId</code> of the <code>WebACL</code> that you want to update. <code>WebACLId</code> is returned by <code>CreateWebACL</code> and by <code>ListWebACLs</code>.</p>
    pub fn set_web_acl_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.web_acl_id = input;
        self
    }
    /// <p>The <code>WebACLId</code> of the <code>WebACL</code> that you want to update. <code>WebACLId</code> is returned by <code>CreateWebACL</code> and by <code>ListWebACLs</code>.</p>
    pub fn get_web_acl_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.web_acl_id
    }
    /// <p>The value returned by the most recent call to <code>GetChangeToken</code>.</p>
    /// This field is required.
    pub fn change_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.change_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value returned by the most recent call to <code>GetChangeToken</code>.</p>
    pub fn set_change_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.change_token = input;
        self
    }
    /// <p>The value returned by the most recent call to <code>GetChangeToken</code>.</p>
    pub fn get_change_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.change_token
    }
    /// Appends an item to `updates`.
    ///
    /// To override the contents of this collection use [`set_updates`](Self::set_updates).
    ///
    /// <p>An array of updates to make to the <code>WebACL</code>.</p>
    /// <p>An array of <code>WebACLUpdate</code> objects that you want to insert into or delete from a <code>WebACL</code>. For more information, see the applicable data types:</p>
    /// <ul>
    /// <li>
    /// <p><code>WebACLUpdate</code>: Contains <code>Action</code> and <code>ActivatedRule</code></p></li>
    /// <li>
    /// <p><code>ActivatedRule</code>: Contains <code>Action</code>, <code>OverrideAction</code>, <code>Priority</code>, <code>RuleId</code>, and <code>Type</code>. <code>ActivatedRule|OverrideAction</code> applies only when updating or adding a <code>RuleGroup</code> to a <code>WebACL</code>. In this case, you do not use <code>ActivatedRule|Action</code>. For all other update requests, <code>ActivatedRule|Action</code> is used instead of <code>ActivatedRule|OverrideAction</code>.</p></li>
    /// <li>
    /// <p><code>WafAction</code>: Contains <code>Type</code></p></li>
    /// </ul>
    pub fn updates(mut self, input: crate::types::WebAclUpdate) -> Self {
        let mut v = self.updates.unwrap_or_default();
        v.push(input);
        self.updates = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of updates to make to the <code>WebACL</code>.</p>
    /// <p>An array of <code>WebACLUpdate</code> objects that you want to insert into or delete from a <code>WebACL</code>. For more information, see the applicable data types:</p>
    /// <ul>
    /// <li>
    /// <p><code>WebACLUpdate</code>: Contains <code>Action</code> and <code>ActivatedRule</code></p></li>
    /// <li>
    /// <p><code>ActivatedRule</code>: Contains <code>Action</code>, <code>OverrideAction</code>, <code>Priority</code>, <code>RuleId</code>, and <code>Type</code>. <code>ActivatedRule|OverrideAction</code> applies only when updating or adding a <code>RuleGroup</code> to a <code>WebACL</code>. In this case, you do not use <code>ActivatedRule|Action</code>. For all other update requests, <code>ActivatedRule|Action</code> is used instead of <code>ActivatedRule|OverrideAction</code>.</p></li>
    /// <li>
    /// <p><code>WafAction</code>: Contains <code>Type</code></p></li>
    /// </ul>
    pub fn set_updates(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::WebAclUpdate>>) -> Self {
        self.updates = input;
        self
    }
    /// <p>An array of updates to make to the <code>WebACL</code>.</p>
    /// <p>An array of <code>WebACLUpdate</code> objects that you want to insert into or delete from a <code>WebACL</code>. For more information, see the applicable data types:</p>
    /// <ul>
    /// <li>
    /// <p><code>WebACLUpdate</code>: Contains <code>Action</code> and <code>ActivatedRule</code></p></li>
    /// <li>
    /// <p><code>ActivatedRule</code>: Contains <code>Action</code>, <code>OverrideAction</code>, <code>Priority</code>, <code>RuleId</code>, and <code>Type</code>. <code>ActivatedRule|OverrideAction</code> applies only when updating or adding a <code>RuleGroup</code> to a <code>WebACL</code>. In this case, you do not use <code>ActivatedRule|Action</code>. For all other update requests, <code>ActivatedRule|Action</code> is used instead of <code>ActivatedRule|OverrideAction</code>.</p></li>
    /// <li>
    /// <p><code>WafAction</code>: Contains <code>Type</code></p></li>
    /// </ul>
    pub fn get_updates(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::WebAclUpdate>> {
        &self.updates
    }
    /// <p>A default action for the web ACL, either ALLOW or BLOCK. AWS WAF performs the default action if a request doesn't match the criteria in any of the rules in a web ACL.</p>
    pub fn default_action(mut self, input: crate::types::WafAction) -> Self {
        self.default_action = ::std::option::Option::Some(input);
        self
    }
    /// <p>A default action for the web ACL, either ALLOW or BLOCK. AWS WAF performs the default action if a request doesn't match the criteria in any of the rules in a web ACL.</p>
    pub fn set_default_action(mut self, input: ::std::option::Option<crate::types::WafAction>) -> Self {
        self.default_action = input;
        self
    }
    /// <p>A default action for the web ACL, either ALLOW or BLOCK. AWS WAF performs the default action if a request doesn't match the criteria in any of the rules in a web ACL.</p>
    pub fn get_default_action(&self) -> &::std::option::Option<crate::types::WafAction> {
        &self.default_action
    }
    /// Consumes the builder and constructs a [`UpdateWebAclInput`](crate::operation::update_web_acl::UpdateWebAclInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_web_acl::UpdateWebAclInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_web_acl::UpdateWebAclInput {
            web_acl_id: self.web_acl_id,
            change_token: self.change_token,
            updates: self.updates,
            default_action: self.default_action,
        })
    }
}
