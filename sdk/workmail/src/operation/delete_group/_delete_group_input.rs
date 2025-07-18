// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteGroupInput {
    /// <p>The organization that contains the group.</p>
    pub organization_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the group to be deleted.</p>
    /// <p>The identifier can be the <i>GroupId</i>, or <i>Groupname</i>. The following identity formats are available:</p>
    /// <ul>
    /// <li>
    /// <p>Group ID: 12345678-1234-1234-1234-123456789012 or S-1-1-12-1234567890-123456789-123456789-1234</p></li>
    /// <li>
    /// <p>Group name: group</p></li>
    /// </ul>
    pub group_id: ::std::option::Option<::std::string::String>,
}
impl DeleteGroupInput {
    /// <p>The organization that contains the group.</p>
    pub fn organization_id(&self) -> ::std::option::Option<&str> {
        self.organization_id.as_deref()
    }
    /// <p>The identifier of the group to be deleted.</p>
    /// <p>The identifier can be the <i>GroupId</i>, or <i>Groupname</i>. The following identity formats are available:</p>
    /// <ul>
    /// <li>
    /// <p>Group ID: 12345678-1234-1234-1234-123456789012 or S-1-1-12-1234567890-123456789-123456789-1234</p></li>
    /// <li>
    /// <p>Group name: group</p></li>
    /// </ul>
    pub fn group_id(&self) -> ::std::option::Option<&str> {
        self.group_id.as_deref()
    }
}
impl DeleteGroupInput {
    /// Creates a new builder-style object to manufacture [`DeleteGroupInput`](crate::operation::delete_group::DeleteGroupInput).
    pub fn builder() -> crate::operation::delete_group::builders::DeleteGroupInputBuilder {
        crate::operation::delete_group::builders::DeleteGroupInputBuilder::default()
    }
}

/// A builder for [`DeleteGroupInput`](crate::operation::delete_group::DeleteGroupInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteGroupInputBuilder {
    pub(crate) organization_id: ::std::option::Option<::std::string::String>,
    pub(crate) group_id: ::std::option::Option<::std::string::String>,
}
impl DeleteGroupInputBuilder {
    /// <p>The organization that contains the group.</p>
    /// This field is required.
    pub fn organization_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.organization_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The organization that contains the group.</p>
    pub fn set_organization_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.organization_id = input;
        self
    }
    /// <p>The organization that contains the group.</p>
    pub fn get_organization_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.organization_id
    }
    /// <p>The identifier of the group to be deleted.</p>
    /// <p>The identifier can be the <i>GroupId</i>, or <i>Groupname</i>. The following identity formats are available:</p>
    /// <ul>
    /// <li>
    /// <p>Group ID: 12345678-1234-1234-1234-123456789012 or S-1-1-12-1234567890-123456789-123456789-1234</p></li>
    /// <li>
    /// <p>Group name: group</p></li>
    /// </ul>
    /// This field is required.
    pub fn group_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.group_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the group to be deleted.</p>
    /// <p>The identifier can be the <i>GroupId</i>, or <i>Groupname</i>. The following identity formats are available:</p>
    /// <ul>
    /// <li>
    /// <p>Group ID: 12345678-1234-1234-1234-123456789012 or S-1-1-12-1234567890-123456789-123456789-1234</p></li>
    /// <li>
    /// <p>Group name: group</p></li>
    /// </ul>
    pub fn set_group_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.group_id = input;
        self
    }
    /// <p>The identifier of the group to be deleted.</p>
    /// <p>The identifier can be the <i>GroupId</i>, or <i>Groupname</i>. The following identity formats are available:</p>
    /// <ul>
    /// <li>
    /// <p>Group ID: 12345678-1234-1234-1234-123456789012 or S-1-1-12-1234567890-123456789-123456789-1234</p></li>
    /// <li>
    /// <p>Group name: group</p></li>
    /// </ul>
    pub fn get_group_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.group_id
    }
    /// Consumes the builder and constructs a [`DeleteGroupInput`](crate::operation::delete_group::DeleteGroupInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::delete_group::DeleteGroupInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_group::DeleteGroupInput {
            organization_id: self.organization_id,
            group_id: self.group_id,
        })
    }
}
