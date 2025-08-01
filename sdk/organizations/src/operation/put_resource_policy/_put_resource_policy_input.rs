// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutResourcePolicyInput {
    /// <p>If provided, the new content for the resource policy. The text must be correctly formatted JSON that complies with the syntax for the resource policy's type. For more information, see <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_syntax.html">SCP syntax</a> in the <i>Organizations User Guide</i>.</p>
    pub content: ::std::option::Option<::std::string::String>,
    /// <p>A list of tags that you want to attach to the newly created resource policy. For each tag in the list, you must specify both a tag key and a value. You can set the value to an empty string, but you can't set it to <code>null</code>. For more information about tagging, see <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_tagging.html">Tagging Organizations resources</a> in the Organizations User Guide.</p><note>
    /// <p>Calls with tags apply to the initial creation of the resource policy, otherwise an exception is thrown. If any one of the tags is not valid or if you exceed the allowed number of tags for the resource policy, then the entire request fails and the resource policy is not created.</p>
    /// </note>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl PutResourcePolicyInput {
    /// <p>If provided, the new content for the resource policy. The text must be correctly formatted JSON that complies with the syntax for the resource policy's type. For more information, see <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_syntax.html">SCP syntax</a> in the <i>Organizations User Guide</i>.</p>
    pub fn content(&self) -> ::std::option::Option<&str> {
        self.content.as_deref()
    }
    /// <p>A list of tags that you want to attach to the newly created resource policy. For each tag in the list, you must specify both a tag key and a value. You can set the value to an empty string, but you can't set it to <code>null</code>. For more information about tagging, see <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_tagging.html">Tagging Organizations resources</a> in the Organizations User Guide.</p><note>
    /// <p>Calls with tags apply to the initial creation of the resource policy, otherwise an exception is thrown. If any one of the tags is not valid or if you exceed the allowed number of tags for the resource policy, then the entire request fails and the resource policy is not created.</p>
    /// </note>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl PutResourcePolicyInput {
    /// Creates a new builder-style object to manufacture [`PutResourcePolicyInput`](crate::operation::put_resource_policy::PutResourcePolicyInput).
    pub fn builder() -> crate::operation::put_resource_policy::builders::PutResourcePolicyInputBuilder {
        crate::operation::put_resource_policy::builders::PutResourcePolicyInputBuilder::default()
    }
}

/// A builder for [`PutResourcePolicyInput`](crate::operation::put_resource_policy::PutResourcePolicyInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutResourcePolicyInputBuilder {
    pub(crate) content: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl PutResourcePolicyInputBuilder {
    /// <p>If provided, the new content for the resource policy. The text must be correctly formatted JSON that complies with the syntax for the resource policy's type. For more information, see <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_syntax.html">SCP syntax</a> in the <i>Organizations User Guide</i>.</p>
    /// This field is required.
    pub fn content(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.content = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If provided, the new content for the resource policy. The text must be correctly formatted JSON that complies with the syntax for the resource policy's type. For more information, see <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_syntax.html">SCP syntax</a> in the <i>Organizations User Guide</i>.</p>
    pub fn set_content(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.content = input;
        self
    }
    /// <p>If provided, the new content for the resource policy. The text must be correctly formatted JSON that complies with the syntax for the resource policy's type. For more information, see <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_syntax.html">SCP syntax</a> in the <i>Organizations User Guide</i>.</p>
    pub fn get_content(&self) -> &::std::option::Option<::std::string::String> {
        &self.content
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A list of tags that you want to attach to the newly created resource policy. For each tag in the list, you must specify both a tag key and a value. You can set the value to an empty string, but you can't set it to <code>null</code>. For more information about tagging, see <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_tagging.html">Tagging Organizations resources</a> in the Organizations User Guide.</p><note>
    /// <p>Calls with tags apply to the initial creation of the resource policy, otherwise an exception is thrown. If any one of the tags is not valid or if you exceed the allowed number of tags for the resource policy, then the entire request fails and the resource policy is not created.</p>
    /// </note>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of tags that you want to attach to the newly created resource policy. For each tag in the list, you must specify both a tag key and a value. You can set the value to an empty string, but you can't set it to <code>null</code>. For more information about tagging, see <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_tagging.html">Tagging Organizations resources</a> in the Organizations User Guide.</p><note>
    /// <p>Calls with tags apply to the initial creation of the resource policy, otherwise an exception is thrown. If any one of the tags is not valid or if you exceed the allowed number of tags for the resource policy, then the entire request fails and the resource policy is not created.</p>
    /// </note>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A list of tags that you want to attach to the newly created resource policy. For each tag in the list, you must specify both a tag key and a value. You can set the value to an empty string, but you can't set it to <code>null</code>. For more information about tagging, see <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_tagging.html">Tagging Organizations resources</a> in the Organizations User Guide.</p><note>
    /// <p>Calls with tags apply to the initial creation of the resource policy, otherwise an exception is thrown. If any one of the tags is not valid or if you exceed the allowed number of tags for the resource policy, then the entire request fails and the resource policy is not created.</p>
    /// </note>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`PutResourcePolicyInput`](crate::operation::put_resource_policy::PutResourcePolicyInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::put_resource_policy::PutResourcePolicyInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::put_resource_policy::PutResourcePolicyInput {
            content: self.content,
            tags: self.tags,
        })
    }
}
