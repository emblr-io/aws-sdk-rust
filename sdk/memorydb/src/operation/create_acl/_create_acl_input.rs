// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateAclInput {
    /// <p>The name of the Access Control List.</p>
    pub acl_name: ::std::option::Option<::std::string::String>,
    /// <p>The list of users that belong to the Access Control List.</p>
    pub user_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>A list of tags to be added to this resource. A tag is a key-value pair. A tag key must be accompanied by a tag value, although null is accepted.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateAclInput {
    /// <p>The name of the Access Control List.</p>
    pub fn acl_name(&self) -> ::std::option::Option<&str> {
        self.acl_name.as_deref()
    }
    /// <p>The list of users that belong to the Access Control List.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.user_names.is_none()`.
    pub fn user_names(&self) -> &[::std::string::String] {
        self.user_names.as_deref().unwrap_or_default()
    }
    /// <p>A list of tags to be added to this resource. A tag is a key-value pair. A tag key must be accompanied by a tag value, although null is accepted.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl CreateAclInput {
    /// Creates a new builder-style object to manufacture [`CreateAclInput`](crate::operation::create_acl::CreateAclInput).
    pub fn builder() -> crate::operation::create_acl::builders::CreateAclInputBuilder {
        crate::operation::create_acl::builders::CreateAclInputBuilder::default()
    }
}

/// A builder for [`CreateAclInput`](crate::operation::create_acl::CreateAclInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateAclInputBuilder {
    pub(crate) acl_name: ::std::option::Option<::std::string::String>,
    pub(crate) user_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateAclInputBuilder {
    /// <p>The name of the Access Control List.</p>
    /// This field is required.
    pub fn acl_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.acl_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Access Control List.</p>
    pub fn set_acl_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.acl_name = input;
        self
    }
    /// <p>The name of the Access Control List.</p>
    pub fn get_acl_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.acl_name
    }
    /// Appends an item to `user_names`.
    ///
    /// To override the contents of this collection use [`set_user_names`](Self::set_user_names).
    ///
    /// <p>The list of users that belong to the Access Control List.</p>
    pub fn user_names(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.user_names.unwrap_or_default();
        v.push(input.into());
        self.user_names = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of users that belong to the Access Control List.</p>
    pub fn set_user_names(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.user_names = input;
        self
    }
    /// <p>The list of users that belong to the Access Control List.</p>
    pub fn get_user_names(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.user_names
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A list of tags to be added to this resource. A tag is a key-value pair. A tag key must be accompanied by a tag value, although null is accepted.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of tags to be added to this resource. A tag is a key-value pair. A tag key must be accompanied by a tag value, although null is accepted.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A list of tags to be added to this resource. A tag is a key-value pair. A tag key must be accompanied by a tag value, although null is accepted.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateAclInput`](crate::operation::create_acl::CreateAclInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::create_acl::CreateAclInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_acl::CreateAclInput {
            acl_name: self.acl_name,
            user_names: self.user_names,
            tags: self.tags,
        })
    }
}
