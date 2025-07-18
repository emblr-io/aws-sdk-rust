// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateUserInput {
    /// <p>The path for the user name. For more information about paths, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html">IAM identifiers</a> in the <i>IAM User Guide</i>.</p>
    /// <p>This parameter is optional. If it is not included, it defaults to a slash (/).</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! (<code>\u0021</code>) through the DEL character (<code>\u007F</code>), including most punctuation characters, digits, and upper and lowercased letters.</p>
    pub path: ::std::option::Option<::std::string::String>,
    /// <p>The name of the user to create.</p>
    /// <p>IAM user, group, role, and policy names must be unique within the account. Names are not distinguished by case. For example, you cannot create resources named both "MyResource" and "myresource".</p>
    pub user_name: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the managed policy that is used to set the permissions boundary for the user.</p>
    /// <p>A permissions boundary policy defines the maximum permissions that identity-based policies can grant to an entity, but does not grant permissions. Permissions boundaries do not define the maximum permissions that a resource-based policy can grant to an entity. To learn more, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html">Permissions boundaries for IAM entities</a> in the <i>IAM User Guide</i>.</p>
    /// <p>For more information about policy types, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html#access_policy-types">Policy types </a> in the <i>IAM User Guide</i>.</p>
    pub permissions_boundary: ::std::option::Option<::std::string::String>,
    /// <p>A list of tags that you want to attach to the new user. Each tag consists of a key name and an associated value. For more information about tagging, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html">Tagging IAM resources</a> in the <i>IAM User Guide</i>.</p><note>
    /// <p>If any one of the tags is invalid or if you exceed the allowed maximum number of tags, then the entire request fails and the resource is not created.</p>
    /// </note>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateUserInput {
    /// <p>The path for the user name. For more information about paths, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html">IAM identifiers</a> in the <i>IAM User Guide</i>.</p>
    /// <p>This parameter is optional. If it is not included, it defaults to a slash (/).</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! (<code>\u0021</code>) through the DEL character (<code>\u007F</code>), including most punctuation characters, digits, and upper and lowercased letters.</p>
    pub fn path(&self) -> ::std::option::Option<&str> {
        self.path.as_deref()
    }
    /// <p>The name of the user to create.</p>
    /// <p>IAM user, group, role, and policy names must be unique within the account. Names are not distinguished by case. For example, you cannot create resources named both "MyResource" and "myresource".</p>
    pub fn user_name(&self) -> ::std::option::Option<&str> {
        self.user_name.as_deref()
    }
    /// <p>The ARN of the managed policy that is used to set the permissions boundary for the user.</p>
    /// <p>A permissions boundary policy defines the maximum permissions that identity-based policies can grant to an entity, but does not grant permissions. Permissions boundaries do not define the maximum permissions that a resource-based policy can grant to an entity. To learn more, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html">Permissions boundaries for IAM entities</a> in the <i>IAM User Guide</i>.</p>
    /// <p>For more information about policy types, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html#access_policy-types">Policy types </a> in the <i>IAM User Guide</i>.</p>
    pub fn permissions_boundary(&self) -> ::std::option::Option<&str> {
        self.permissions_boundary.as_deref()
    }
    /// <p>A list of tags that you want to attach to the new user. Each tag consists of a key name and an associated value. For more information about tagging, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html">Tagging IAM resources</a> in the <i>IAM User Guide</i>.</p><note>
    /// <p>If any one of the tags is invalid or if you exceed the allowed maximum number of tags, then the entire request fails and the resource is not created.</p>
    /// </note>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl CreateUserInput {
    /// Creates a new builder-style object to manufacture [`CreateUserInput`](crate::operation::create_user::CreateUserInput).
    pub fn builder() -> crate::operation::create_user::builders::CreateUserInputBuilder {
        crate::operation::create_user::builders::CreateUserInputBuilder::default()
    }
}

/// A builder for [`CreateUserInput`](crate::operation::create_user::CreateUserInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateUserInputBuilder {
    pub(crate) path: ::std::option::Option<::std::string::String>,
    pub(crate) user_name: ::std::option::Option<::std::string::String>,
    pub(crate) permissions_boundary: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateUserInputBuilder {
    /// <p>The path for the user name. For more information about paths, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html">IAM identifiers</a> in the <i>IAM User Guide</i>.</p>
    /// <p>This parameter is optional. If it is not included, it defaults to a slash (/).</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! (<code>\u0021</code>) through the DEL character (<code>\u007F</code>), including most punctuation characters, digits, and upper and lowercased letters.</p>
    pub fn path(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.path = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The path for the user name. For more information about paths, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html">IAM identifiers</a> in the <i>IAM User Guide</i>.</p>
    /// <p>This parameter is optional. If it is not included, it defaults to a slash (/).</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! (<code>\u0021</code>) through the DEL character (<code>\u007F</code>), including most punctuation characters, digits, and upper and lowercased letters.</p>
    pub fn set_path(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.path = input;
        self
    }
    /// <p>The path for the user name. For more information about paths, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html">IAM identifiers</a> in the <i>IAM User Guide</i>.</p>
    /// <p>This parameter is optional. If it is not included, it defaults to a slash (/).</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! (<code>\u0021</code>) through the DEL character (<code>\u007F</code>), including most punctuation characters, digits, and upper and lowercased letters.</p>
    pub fn get_path(&self) -> &::std::option::Option<::std::string::String> {
        &self.path
    }
    /// <p>The name of the user to create.</p>
    /// <p>IAM user, group, role, and policy names must be unique within the account. Names are not distinguished by case. For example, you cannot create resources named both "MyResource" and "myresource".</p>
    /// This field is required.
    pub fn user_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the user to create.</p>
    /// <p>IAM user, group, role, and policy names must be unique within the account. Names are not distinguished by case. For example, you cannot create resources named both "MyResource" and "myresource".</p>
    pub fn set_user_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_name = input;
        self
    }
    /// <p>The name of the user to create.</p>
    /// <p>IAM user, group, role, and policy names must be unique within the account. Names are not distinguished by case. For example, you cannot create resources named both "MyResource" and "myresource".</p>
    pub fn get_user_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_name
    }
    /// <p>The ARN of the managed policy that is used to set the permissions boundary for the user.</p>
    /// <p>A permissions boundary policy defines the maximum permissions that identity-based policies can grant to an entity, but does not grant permissions. Permissions boundaries do not define the maximum permissions that a resource-based policy can grant to an entity. To learn more, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html">Permissions boundaries for IAM entities</a> in the <i>IAM User Guide</i>.</p>
    /// <p>For more information about policy types, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html#access_policy-types">Policy types </a> in the <i>IAM User Guide</i>.</p>
    pub fn permissions_boundary(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.permissions_boundary = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the managed policy that is used to set the permissions boundary for the user.</p>
    /// <p>A permissions boundary policy defines the maximum permissions that identity-based policies can grant to an entity, but does not grant permissions. Permissions boundaries do not define the maximum permissions that a resource-based policy can grant to an entity. To learn more, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html">Permissions boundaries for IAM entities</a> in the <i>IAM User Guide</i>.</p>
    /// <p>For more information about policy types, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html#access_policy-types">Policy types </a> in the <i>IAM User Guide</i>.</p>
    pub fn set_permissions_boundary(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.permissions_boundary = input;
        self
    }
    /// <p>The ARN of the managed policy that is used to set the permissions boundary for the user.</p>
    /// <p>A permissions boundary policy defines the maximum permissions that identity-based policies can grant to an entity, but does not grant permissions. Permissions boundaries do not define the maximum permissions that a resource-based policy can grant to an entity. To learn more, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html">Permissions boundaries for IAM entities</a> in the <i>IAM User Guide</i>.</p>
    /// <p>For more information about policy types, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html#access_policy-types">Policy types </a> in the <i>IAM User Guide</i>.</p>
    pub fn get_permissions_boundary(&self) -> &::std::option::Option<::std::string::String> {
        &self.permissions_boundary
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A list of tags that you want to attach to the new user. Each tag consists of a key name and an associated value. For more information about tagging, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html">Tagging IAM resources</a> in the <i>IAM User Guide</i>.</p><note>
    /// <p>If any one of the tags is invalid or if you exceed the allowed maximum number of tags, then the entire request fails and the resource is not created.</p>
    /// </note>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of tags that you want to attach to the new user. Each tag consists of a key name and an associated value. For more information about tagging, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html">Tagging IAM resources</a> in the <i>IAM User Guide</i>.</p><note>
    /// <p>If any one of the tags is invalid or if you exceed the allowed maximum number of tags, then the entire request fails and the resource is not created.</p>
    /// </note>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A list of tags that you want to attach to the new user. Each tag consists of a key name and an associated value. For more information about tagging, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html">Tagging IAM resources</a> in the <i>IAM User Guide</i>.</p><note>
    /// <p>If any one of the tags is invalid or if you exceed the allowed maximum number of tags, then the entire request fails and the resource is not created.</p>
    /// </note>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateUserInput`](crate::operation::create_user::CreateUserInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::create_user::CreateUserInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_user::CreateUserInput {
            path: self.path,
            user_name: self.user_name,
            permissions_boundary: self.permissions_boundary,
            tags: self.tags,
        })
    }
}
